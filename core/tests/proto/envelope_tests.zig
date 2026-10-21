//! Тесты протокола конвертов (envelope.zig): roundtrip'и, раскладки
//! байтов little-endian, строгий decode, границы лимитов, entities,
//! punch/v6addr, SYNC-хвост. Корень — шаг test-proto (zig build test-proto).
const std = @import("std");
const stille_messenger = @import("stille-messenger");
const envelope = stille_messenger.proto.envelope;
const codec = stille_messenger.proto.codec;

const testing = std.testing;
const Tag = envelope.Tag;
const Envelope = envelope.Envelope;
const Text = envelope.Text;
const ReplyText = envelope.ReplyText;
const React = envelope.React;
const Ack = envelope.Ack;
const BlockNotice = envelope.BlockNotice;
const PresencePing = envelope.PresencePing;
const PresencePong = envelope.PresencePong;
const CallSignal = envelope.CallSignal;
const CallAudio = envelope.CallAudio;
const Profile = envelope.Profile;
const Avatar = envelope.Avatar;
const AvatarAck = envelope.AvatarAck;
const AvatarReq = envelope.AvatarReq;
const FileMeta = envelope.FileMeta;
const FileData = envelope.FileData;
const FileAck = envelope.FileAck;
const ContactCard = envelope.ContactCard;
const Sync = envelope.Sync;
const SyncAck = envelope.SyncAck;
const RatchetKey = envelope.RatchetKey;
const Join = envelope.Join;
const Punch = envelope.Punch;
const V6Addr = envelope.V6Addr;
const TextEntity = envelope.TextEntity;
const EntityKind = envelope.EntityKind;
const EntitiesError = envelope.EntitiesError;
const SyncRecView = envelope.SyncRecView;
const decode = envelope.decode;
const encode = envelope.encode;
const encodedLen = envelope.encodedLen;
const parseEntities = envelope.parseEntities;
const encodeEntitiesTail = envelope.encodeEntitiesTail;
const validateEntities = envelope.validateEntities;
const parseSyncRecs = envelope.parseSyncRecs;
const EncodeError = envelope.EncodeError;
const DecodeError = envelope.DecodeError;
const max_join_name = envelope.max_join_name;
const join_sig_len = envelope.join_sig_len;
const join_hmac_len = envelope.join_hmac_len;
const react_add = envelope.react_add;
const react_remove = envelope.react_remove;
const call_offer = envelope.call_offer;
const call_accept = envelope.call_accept;
const call_reject = envelope.call_reject;
const call_end = envelope.call_end;
const id_len = envelope.id_len;
const max_text_body = envelope.max_text_body;
const max_text_entities = envelope.max_text_entities;
const max_entity_value = envelope.max_entity_value;
const max_text_tail = envelope.max_text_tail;
const max_audio_data = envelope.max_audio_data;
const max_avatar_data = envelope.max_avatar_data;
const max_file_chunk = envelope.max_file_chunk;
const max_file_name = envelope.max_file_name;
const max_card_name = envelope.max_card_name;
const max_card_addr = envelope.max_card_addr;
const max_sync_recs = envelope.max_sync_recs;
const max_sync_rec_data = envelope.max_sync_rec_data;
const sync_mac_len = envelope.sync_mac_len;
const max_sync_tail = envelope.max_sync_tail;
const max_encoded_len = envelope.max_encoded_len;
const max_punch_candidates = envelope.max_punch_candidates;
const punch_host = envelope.punch_host;
const punch_reflexive = envelope.punch_reflexive;
const max_v6_addrs = envelope.max_v6_addrs;

/// Тестовый хелпер: массив `n` одинаковых байтов `value`.
fn filled(comptime n: usize, value: u8) [n]u8 {
    return @splat(value);
}

fn sampleText() Envelope {
    return .{ .text = .{
        .msg_id = .{
            0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18,
            0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90,
        },
        .ts_ms = 1_700_000_000_123,
        .body = "шёпот",
    } };
}

test "TEXT: roundtrip" {
    var buf: [max_encoded_len]u8 = undefined;
    const src = sampleText();
    const wire = try encode(&buf, src);
    try testing.expectEqual(encodedLen(src), wire.len);

    const back = try decode(wire);
    try testing.expectEqualSlices(u8, &src.text.msg_id, &back.text.msg_id);
    try testing.expectEqual(src.text.ts_ms, back.text.ts_ms);
    try testing.expectEqualStrings(src.text.body, back.text.body);
    // хвост: один байт счётчика 0
    try testing.expectEqual(@as(usize, 1), back.text.ents_tail.len);
    try testing.expectEqual(@as(u8, 0), back.text.ents_tail[0]);
    try testing.expectEqual(@as(usize, 0), try parseEntities(back.text.ents_tail, back.text.body.len, null));
}

test "TEXT: раскладка байтов little-endian" {
    var buf: [64]u8 = undefined;
    var msg_id: [id_len]u8 = @splat(0);
    msg_id[0] = 1;
    msg_id[1] = 2;
    const wire = try encode(&buf, .{ .text = .{
        .msg_id = msg_id,
        .ts_ms = 1,
        .body = "ab",
    } });
    try testing.expectEqualSlices(u8, &.{
        0x10, // тег
        1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // msg_id
        1, 0, 0, 0, 0, 0, 0, 0, // ts_ms LE
        2, 0, // длина тела LE
        'a', 'b', // тело
        0, // счётчик entities = 0 (хвост есть всегда)
    }, wire);
}

test "TEXT: пустое тело и максимум 4096" {
    var buf: [max_encoded_len]u8 = undefined;

    const empty: Envelope = .{ .text = .{ .msg_id = filled(id_len, 0), .ts_ms = 0, .body = "" } };
    const back_empty = try decode(try encode(&buf, empty));
    try testing.expectEqual(@as(usize, 0), back_empty.text.body.len);

    var body: [max_text_body]u8 = undefined;
    @memset(&body, 'x');
    const full: Envelope = .{ .text = .{ .msg_id = filled(id_len, 1), .ts_ms = 5, .body = &body } };
    const wire = try encode(&buf, full);
    try testing.expectEqual(1 + id_len + 8 + 2 + max_text_body + 1, wire.len);
    const back_full = try decode(wire);
    try testing.expectEqualSlices(u8, &body, back_full.text.body);
    try testing.expect(back_full.text.body.ptr == wire.ptr + 1 + id_len + 8 + 2); // срез wire, без копии
}

test "TEXT: entities — раскладка хвоста и roundtrip" {
    var buf: [max_encoded_len]u8 = undefined;
    var tail_buf: [max_text_tail]u8 = undefined;

    const ents = [_]TextEntity{
        .{ .kind = .bold, .offset = 0, .len = 2 },
        .{ .kind = .link, .offset = 3, .len = 4, .value = "https://stille-messenger.local" },
    };
    const tail = try encodeEntitiesTail(&tail_buf, &ents, "abcdefg".len);
    // [count][kind, offset LE, len LE, vlen, value...]
    const link = "https://stille-messenger.local";
    var expected: [13 + link.len]u8 = undefined;
    @memcpy(expected[0..13], &[_]u8{ 2, 1, 0, 0, 2, 0, 0, 8, 3, 0, 4, 0, link.len });
    @memcpy(expected[13..], link);
    try testing.expectEqualSlices(u8, &expected, tail);

    const src: Envelope = .{ .text = .{
        .msg_id = filled(id_len, 1),
        .ts_ms = 9,
        .body = "abcdefg",
        .ents_tail = tail,
    } };
    const wire = try encode(&buf, src);
    try testing.expectEqual(encodedLen(src), wire.len);

    const back = try decode(wire);
    try testing.expectEqualStrings(tail, back.text.ents_tail);
    var out: [max_text_entities]TextEntity = undefined;
    const n = try parseEntities(back.text.ents_tail, back.text.body.len, &out);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqual(EntityKind.bold, out[0].kind);
    try testing.expectEqual(@as(u16, 0), out[0].offset);
    try testing.expectEqual(@as(u16, 2), out[0].len);
    try testing.expectEqualStrings("", out[0].value);
    try testing.expectEqual(EntityKind.link, out[1].kind);
    try testing.expectEqual(@as(u16, 3), out[1].offset);
    try testing.expectEqual(@as(u16, 4), out[1].len);
    try testing.expectEqualStrings("https://stille-messenger.local", out[1].value);
}

test "entities: parseEntities отвергает мусор" {
    const blen: usize = 7;
    // выход за тело / len == 0
    try testing.expectError(error.OutOfRange, parseEntities(&[_]u8{ 1, 1, 0, 0, 9, 0, 0 }, blen, null));
    try testing.expectError(error.OutOfRange, parseEntities(&[_]u8{ 1, 1, 0, 0, 0, 0, 0 }, blen, null));
    // не отсортировано (offset 3, затем offset 1)
    try testing.expectError(error.Unsorted, parseEntities(&[_]u8{ 2, 1, 3, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0 }, blen, null));
    // link без URL
    try testing.expectError(error.BadValue, parseEntities(&[_]u8{ 1, 8, 0, 0, 2, 0, 0 }, blen, null));
    // bold со value
    try testing.expectError(error.BadValue, parseEntities(&[_]u8{ 1, 1, 0, 0, 2, 0, 1, 'x' }, blen, null));
    // неизвестный kind
    try testing.expectError(error.BadKind, parseEntities(&[_]u8{ 1, 99, 0, 0, 2, 0, 0 }, blen, null));
    // лишний байт после последней записи
    try testing.expectError(error.BadLen, parseEntities(&[_]u8{ 1, 1, 0, 0, 2, 0, 0, 0xFF }, blen, null));
    // счётчик больше max_text_entities
    try testing.expectError(error.TooMany, parseEntities(&[_]u8{33}, blen, null));
    // обрезано: нет счётчика / нет хвоста записи
    try testing.expectError(error.Truncated, parseEntities(&[_]u8{}, blen, null));
    try testing.expectError(error.Truncated, parseEntities(&[_]u8{ 1, 1, 0, 0, 2, 0 }, blen, null));
}

test "entities: encodeEntitiesTail — лимиты и буфер" {
    var tail_buf: [max_text_tail]u8 = undefined;
    // 33 записи — TooMany (валидация до записи в буфер)
    var ents: [max_text_entities + 1]TextEntity = undefined;
    for (&ents, 0..) |*e, i| e.* = .{ .kind = .bold, .offset = @intCast(i), .len = 1 };
    try testing.expectError(error.TooMany, encodeEntitiesTail(&tail_buf, &ents, max_text_body));
    // буфер короче хвоста — NoSpace
    var small: [3]u8 = undefined;
    try testing.expectError(error.NoSpace, encodeEntitiesTail(&small, &.{.{ .kind = .bold, .offset = 0, .len = 1 }}, 4));
    // граница тела — OutOfRange
    try testing.expectError(error.OutOfRange, encodeEntitiesTail(&tail_buf, &.{.{ .kind = .bold, .offset = 6, .len = 2 }}, 7));
}

test "TEXT: максимум entities — 32 link с value 255, тело 4096" {
    var buf: [max_encoded_len]u8 = undefined;
    var tail_buf: [max_text_tail]u8 = undefined;
    var value: [max_entity_value]u8 = undefined;
    @memset(&value, 'u');

    var ents: [max_text_entities]TextEntity = undefined;
    for (&ents, 0..) |*e, i| {
        e.* = .{ .kind = .link, .offset = @intCast(i * 128), .len = 1, .value = &value };
    }
    const tail = try encodeEntitiesTail(&tail_buf, &ents, max_text_body);
    try testing.expectEqual(@as(usize, 1 + max_text_entities * (6 + max_entity_value)), tail.len);

    var body: [max_text_body]u8 = undefined;
    @memset(&body, 'x');
    const src: Envelope = .{ .text = .{
        .msg_id = filled(id_len, 2),
        .ts_ms = 0,
        .body = &body,
        .ents_tail = tail,
    } };
    const wire = try encode(&buf, src);
    try testing.expectEqual(1 + id_len + 8 + 2 + max_text_body + max_text_tail, wire.len);

    const back = try decode(wire);
    var out: [max_text_entities]TextEntity = undefined;
    try testing.expectEqual(max_text_entities, try parseEntities(back.text.ents_tail, back.text.body.len, &out));
    try testing.expectEqualSlices(u8, &value, out[31].value);
}

test "TEXT: decode с битым хвостом entities -> BadLen, v3-кадр без хвоста -> Truncated" {
    var buf: [max_encoded_len]u8 = undefined;
    const tail = [_]u8{ 1, 1, 0, 0, 2, 0, 0 };
    const good = try encode(&buf, .{ .text = .{
        .msg_id = filled(id_len, 0),
        .ts_ms = 0,
        .body = "abcd",
        .ents_tail = &tail,
    } });
    // v3-кадр: хвост срезан целиком (нет байта счётчика) — Truncated
    try testing.expectError(error.Truncated, decode(good[0 .. good.len - tail.len]));
    // битый хвост: лишний байт после записи — BadLen
    var bytes: [1 + id_len + 8 + 2 + 4 + 8]u8 = undefined;
    var w = codec.Writer.init(&bytes);
    try w.put(@backingInt(Tag.text));
    try w.putFixed(&filled(id_len, 0));
    try w.putInt(u64, 0);
    try w.putBytes("abcd");
    try w.putFixed(&[_]u8{ 1, 1, 0, 0, 2, 0, 0, 0xFF });
    try testing.expectError(error.BadLen, decode(w.buf[0..w.pos]));
}

test "REACT: roundtrip" {
    var buf: [32]u8 = undefined;
    const src: Envelope = .{
        .react = .{
            .msg_id = filled(id_len, 7),
            .op = react_add,
            .code = 0x2764, // U+2764 = ❤
        },
    };
    const wire = try encode(&buf, src);
    try testing.expectEqual(@as(usize, 1 + id_len + 1 + 4), wire.len);

    const back = try decode(wire);
    try testing.expectEqualSlices(u8, &src.react.msg_id, &back.react.msg_id);
    try testing.expectEqual(react_add, back.react.op);
    try testing.expectEqual(@as(u32, 0x2764), back.react.code);

    const rm: Envelope = .{ .react = .{ .msg_id = filled(id_len, 8), .op = react_remove, .code = 3 } };
    const back_rm = try decode(try encode(&buf, rm));
    try testing.expectEqual(react_remove, back_rm.react.op);
}

test "REPLY_TEXT: roundtrip" {
    var buf: [max_encoded_len]u8 = undefined;
    const src: Envelope = .{ .reply_text = .{
        .msg_id = filled(id_len, 1),
        .ts_ms = 1_700_000_000_123,
        .reply_to = filled(id_len, 2),
        .body = "reply",
    } };
    const wire = try encode(&buf, src);
    try testing.expectEqual(1 + id_len + 8 + id_len + 2 + 5 + 1, wire.len);
    const back = try decode(wire);
    try testing.expectEqualSlices(u8, &src.reply_text.msg_id, &back.reply_text.msg_id);
    try testing.expectEqual(src.reply_text.ts_ms, back.reply_text.ts_ms);
    try testing.expectEqualSlices(u8, &src.reply_text.reply_to, &back.reply_text.reply_to);
    try testing.expectEqualStrings(src.reply_text.body, back.reply_text.body);
    // пустой хвост — один нулевой байт счётчика
    try testing.expectEqual(@as(usize, 1), back.reply_text.ents_tail.len);
    try testing.expectEqual(@as(u8, 0), back.reply_text.ents_tail[0]);
}

test "decode: REPLY_TEXT entities и oversize body" {
    var buf: [max_encoded_len]u8 = undefined;
    const tail = [_]u8{ 1, 1, 0, 0, 2, 0, 0 };
    const src: Envelope = .{ .reply_text = .{
        .msg_id = filled(id_len, 0),
        .ts_ms = 0,
        .reply_to = filled(id_len, 9),
        .body = "abcd",
        .ents_tail = &tail,
    } };
    const wire = try encode(&buf, src);
    const back = try decode(wire);
    try testing.expectEqualSlices(u8, &src.reply_text.reply_to, &back.reply_text.reply_to);
    var out: [4]TextEntity = undefined;
    try testing.expectEqual(@as(usize, 1), try parseEntities(back.reply_text.ents_tail, 4, &out));
    try testing.expectEqual(@as(u8, 1), @backingInt(out[0].kind));
    // тело > 4096 → BadLen
    var big_body: [max_text_body + 1]u8 = undefined;
    @memset(&big_body, 'x');
    const too_big: Envelope = .{ .reply_text = .{
        .msg_id = filled(id_len, 0),
        .ts_ms = 0,
        .reply_to = filled(id_len, 0),
        .body = &big_body,
    } };
    try testing.expectError(error.TooBig, encode(&buf, too_big));
}

test "BLOCK_NOTICE: roundtrip" {
    var buf: [8]u8 = undefined;
    const wire = try encode(&buf, .{ .block_notice = .{ .reason = 5 } });
    try testing.expectEqualSlices(u8, &.{ 0x14, 5 }, wire);

    const back = try decode(wire);
    try testing.expectEqual(@as(u8, 5), back.block_notice.reason);
}

test "PRESENCE_PING/PONG: roundtrip" {
    var buf: [16]u8 = undefined;

    const ping: Envelope = .{ .presence_ping = .{ .seq = 0x11223344, .ts_ms = 0x0102030405060708 } };
    const back_ping = try decode(try encode(&buf, ping));
    try testing.expectEqual(@as(u32, 0x11223344), back_ping.presence_ping.seq);
    try testing.expectEqual(@as(u64, 0x0102030405060708), back_ping.presence_ping.ts_ms);

    const pong: Envelope = .{ .presence_pong = .{ .seq = 0x11223344, .ts_peer_ms = 0xF1F2F3F4F5F6F7F8 } };
    const back_pong = try decode(try encode(&buf, pong));
    try testing.expectEqual(@as(u32, 0x11223344), back_pong.presence_pong.seq);
    try testing.expectEqual(@as(u64, 0xF1F2F3F4F5F6F7F8), back_pong.presence_pong.ts_peer_ms);
}

test "CALL_SIGNAL: roundtrip всех опов" {
    var buf: [32]u8 = undefined;
    const ops = [_]u8{ call_offer, call_accept, call_reject, call_end };
    for (ops) |op| {
        const src: Envelope = .{ .call_signal = .{ .op = op, .call_id = filled(id_len, op) } };
        const wire = try encode(&buf, src);
        try testing.expectEqual(@as(usize, 1 + 1 + id_len), wire.len);

        const back = try decode(wire);
        try testing.expectEqual(op, back.call_signal.op);
        try testing.expectEqualSlices(u8, &src.call_signal.call_id, &back.call_signal.call_id);
    }
}

test "CALL_AUDIO: roundtrip" {
    var buf: [1 + 4 + 2 + max_audio_data]u8 = undefined;
    var data: [max_audio_data]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i);

    const src: Envelope = .{ .call_audio = .{ .seq = 777, .data = &data } };
    const wire = try encode(&buf, src);
    try testing.expectEqual(@as(usize, 1 + 4 + 2 + max_audio_data), wire.len);

    const back = try decode(wire);
    try testing.expectEqual(@as(u32, 777), back.call_audio.seq);
    try testing.expectEqualSlices(u8, &data, back.call_audio.data);

    const silent: Envelope = .{ .call_audio = .{ .seq = 778, .data = "" } };
    const back_silent = try decode(try encode(&buf, silent));
    try testing.expectEqual(@as(usize, 0), back_silent.call_audio.data.len);
}

test "decode: неизвестный тег 0x7F -> UnknownTag" {
    const bytes: [8]u8 = @splat(0x7F);
    try testing.expectError(error.UnknownTag, decode(&bytes));
    try testing.expectError(error.UnknownTag, decode(&[_]u8{0x7F}));
    try testing.expectError(error.UnknownTag, decode(&[_]u8{0x12})); // дырка между тегами
}

test "punch: roundtrip кандидатов + encodedLen" {
    var p: Punch = .{
        .count = 3,
        .types = .{ punch_reflexive, punch_host, punch_reflexive, 0, 0, 0, 0, 0 },
        .ips = .{ .{ 203, 0, 113, 7 }, .{ 192, 168, 1, 42 }, .{ 198, 51, 100, 9 }, .{ 0, 0, 0, 0 }, .{ 0, 0, 0, 0 }, .{ 0, 0, 0, 0 }, .{ 0, 0, 0, 0 }, .{ 0, 0, 0, 0 } },
        .ports = .{ 40123, 7777, 51234, 0, 0, 0, 0, 0 },
    };
    const want_len = 1 + 1 + 3 * (1 + 4 + 2);
    try testing.expectEqual(want_len, encodedLen(.{ .punch = p }));
    var buf: [max_encoded_len]u8 = undefined;
    const wire = try encode(&buf, .{ .punch = p });
    try testing.expectEqual(want_len, wire.len);
    const back = try decode(wire);
    const q = back.punch;
    try testing.expectEqual(@as(u8, 3), q.count);
    for (0..3) |i| {
        try testing.expectEqual(p.types[i], q.types[i]);
        try testing.expectEqualSlices(u8, &p.ips[i], &q.ips[i]);
        try testing.expectEqual(p.ports[i], q.ports[i]);
    }
}

test "punch: битые кадры -> BadLen/Truncated" {
    // count = 0
    try testing.expectError(error.BadLen, decode(&[_]u8{ 0x47, 0 }));
    // count = 9 (лимит 8)
    try testing.expectError(error.BadLen, decode(&[_]u8{ 0x47, 9 }));
    // неизвестный тип записи (2)
    try testing.expectError(error.BadLen, decode(&[_]u8{ 0x47, 1, 2, 10, 0, 0, 1, 0, 0 }));
    // усечённая запись (нет порта)
    try testing.expectError(error.Truncated, decode(&[_]u8{ 0x47, 1, 1, 10, 0, 0, 1 }));
    // лишний байт хвоста
    try testing.expectError(error.BadLen, decode(&[_]u8{ 0x47, 1, 1, 10, 0, 0, 1, 0, 0, 0 }));
    // encode: count вне лимита
    var bad: Punch = .{ .count = 9, .types = @splat(0), .ips = @splat(@splat(0)), .ports = @splat(0) };
    var buf: [max_encoded_len]u8 = undefined;
    try testing.expectError(error.BadLen, encode(&buf, .{ .punch = bad }));
    bad.count = 0;
    try testing.expectError(error.BadLen, encode(&buf, .{ .punch = bad }));
}

test "decode: любой обрезанный кадр -> Truncated" {
    var buf: [max_encoded_len]u8 = undefined;
    const cases = [_]Envelope{
        sampleText(),
        .{ .react = .{ .msg_id = filled(id_len, 1), .op = react_add, .code = 1 } },
        .{ .block_notice = .{ .reason = 1 } },
        .{ .presence_ping = .{ .seq = 1, .ts_ms = 1 } },
        .{ .presence_pong = .{ .seq = 1, .ts_peer_ms = 1 } },
        .{ .call_signal = .{ .op = call_offer, .call_id = filled(id_len, 2) } },
        .{ .call_audio = .{ .seq = 1, .data = "abc" } },
        .{ .reply_text = .{ .msg_id = filled(id_len, 1), .ts_ms = 1, .reply_to = filled(id_len, 2), .body = "abc" } },
    };
    for (cases) |case| {
        const wire = try encode(&buf, case);
        var cut: usize = 0;
        while (cut < wire.len) : (cut += 1) {
            try testing.expectError(error.Truncated, decode(wire[0..cut]));
        }
    }
}

test "decode: длина тела заявлена, байтов меньше -> Truncated" {
    var bytes: [1 + id_len + 8 + 2 + 3]u8 = undefined;
    var w = codec.Writer.init(&bytes);
    try w.put(@backingInt(Tag.text));
    try w.putFixed(&filled(id_len, 0));
    try w.putInt(u64, 0);
    try w.putInt(u16, 10); // обещано 10 байтов тела
    try w.putFixed("abc"); // есть только 3
    try testing.expectError(error.Truncated, decode(w.buf[0..w.pos]));
}

test "decode: лишний хвост после кадра -> BadLen" {
    var buf: [max_encoded_len + 1]u8 = undefined;
    const wire = try encode(buf[0..max_encoded_len], sampleText());
    buf[wire.len] = 0xFF;
    try testing.expectError(error.BadLen, decode(buf[0 .. wire.len + 1]));
}

test "decode: тело TEXT больше максимума -> BadLen" {
    var bytes: [1 + id_len + 8 + 2 + max_text_body + 1]u8 = undefined;
    var w = codec.Writer.init(&bytes);
    const overflow: [max_text_body + 1]u8 = @splat(0);
    try w.put(@backingInt(Tag.text));
    try w.putFixed(&filled(id_len, 0));
    try w.putInt(u64, 0);
    try w.putInt(u16, max_text_body + 1);
    try w.putFixed(&overflow);
    try testing.expectError(error.BadLen, decode(w.buf[0..w.pos]));
}

test "decode: DATA в CALL_AUDIO больше максимума -> BadLen" {
    var bytes: [1 + 4 + 2 + max_audio_data + 1]u8 = undefined;
    var w = codec.Writer.init(&bytes);
    const overflow: [max_audio_data + 1]u8 = @splat(0);
    try w.put(@backingInt(Tag.call_audio));
    try w.putInt(u32, 0);
    try w.putInt(u16, max_audio_data + 1);
    try w.putFixed(&overflow);
    try testing.expectError(error.BadLen, decode(w.buf[0..w.pos]));
}

test "encode: тело TEXT > 4096 -> TooBig, DATA > 1024 -> TooBig" {
    var big_buf: [max_encoded_len + 64]u8 = undefined;

    var big_body: [max_text_body + 1]u8 = undefined;
    @memset(&big_body, 'x');
    const big_text: Envelope = .{ .text = .{ .msg_id = filled(id_len, 0), .ts_ms = 0, .body = &big_body } };
    try testing.expectError(error.TooBig, encode(&big_buf, big_text));

    var big_data: [max_audio_data + 1]u8 = undefined;
    @memset(&big_data, 'y');
    const big_audio: Envelope = .{ .call_audio = .{ .seq = 0, .data = &big_data } };
    try testing.expectError(error.TooBig, encode(&big_buf, big_audio));
}

test "encode: слишком маленький буфер -> NoSpace" {
    var buf: [8]u8 = undefined;
    try testing.expectError(error.NoSpace, encode(&buf, sampleText()));
    try testing.expectError(error.NoSpace, encode(buf[0..0], sampleText()));
    // BLOCK_NOTICE занимает 2 байта — в один байт не влезает.
    try testing.expectError(error.NoSpace, encode(buf[0..1], .{ .block_notice = .{ .reason = 0 } }));
}

test "envelope: JOIN roundtrip" {
    var buf: [max_encoded_len]u8 = undefined;
    const e = Envelope{ .join = .{
        .bundle = filled(64, 0x5A),
        .name = "mom",
        .sig = filled(64, 0x77),
        .hmac = filled(32, 0x33),
    } };
    const bytes = try encode(&buf, e);
    try testing.expectEqual(1 + 64 + 1 + 3 + 64 + 32, bytes.len);
    const back = try decode(bytes);
    try testing.expectEqualSlices(u8, &filled(64, 0x5A), &back.join.bundle);
    try testing.expectEqualStrings("mom", back.join.name);
    try testing.expectEqualSlices(u8, &filled(64, 0x77), &back.join.sig);
    try testing.expectEqualSlices(u8, &filled(32, 0x33), &back.join.hmac);
    // мусорный хвост — BadLen
    try testing.expectError(error.Truncated, decode(bytes[0 .. bytes.len - 1]));
}

test "envelope: RATCHET_KEY roundtrip" {
    var buf: [max_encoded_len]u8 = undefined;
    const e = Envelope{ .ratchet_key = .{
        .epoch = 0x0304,
        .dh_pub = filled(32, 0xA5),
    } };
    const bytes = try encode(&buf, e);
    try testing.expectEqual(@as(usize, 1 + 2 + 32), bytes.len);
    // тег 0x44, epoch u16 LE
    try testing.expectEqual(@as(u8, 0x44), bytes[0]);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x04, 0x03 }, bytes[1..3]);

    const back = try decode(bytes);
    try testing.expectEqual(@as(u16, 0x0304), back.ratchet_key.epoch);
    try testing.expectEqualSlices(u8, &filled(32, 0xA5), &back.ratchet_key.dh_pub);
    // обрезанный/с хвостом
    try testing.expectError(error.Truncated, decode(bytes[0 .. bytes.len - 1]));
    var with_tail: [40]u8 = undefined;
    @memcpy(with_tail[0..bytes.len], bytes);
    with_tail[bytes.len] = 0;
    try testing.expectError(error.BadLen, decode(with_tail[0 .. bytes.len + 1]));
}

test "envelope: CONTACT_CARD roundtrip" {
    var buf: [max_encoded_len]u8 = undefined;
    const e = Envelope{ .contact_card = .{
        .name = "алиса",
        .bundle = filled(64, 0x3B),
        .addr = "10.0.0.7:7779",
    } };
    const bytes = try encode(&buf, e);
    // тег 0x43, имя u8+байты, bundle 64, адрес u16+байты
    try testing.expectEqual(@as(u8, 0x43), bytes[0]);
    try testing.expectEqual(@as(usize, 1 + 1 + "алиса".len + 64 + 2 + "10.0.0.7:7779".len), bytes.len);

    const back = try decode(bytes);
    try testing.expectEqualStrings("алиса", back.contact_card.name);
    try testing.expectEqualSlices(u8, &filled(64, 0x3B), &back.contact_card.bundle);
    try testing.expectEqualStrings("10.0.0.7:7779", back.contact_card.addr);

    // обрезанный/с хвостом (до перезаписи буфера вторым конвертом)
    try testing.expectError(error.Truncated, decode(bytes[0 .. bytes.len - 1]));
    var with_tail: [128]u8 = undefined;
    @memcpy(with_tail[0..bytes.len], bytes);
    with_tail[bytes.len] = 0;
    try testing.expectError(error.BadLen, decode(with_tail[0 .. bytes.len + 1]));

    // пустой адрес валиден (адрес неизвестен)
    const e2 = Envelope{ .contact_card = .{
        .name = "б",
        .bundle = filled(64, 1),
        .addr = "",
    } };
    const b2 = try encode(&buf, e2);
    const back2 = try decode(b2);
    try testing.expectEqual(@as(usize, 0), back2.contact_card.addr.len);
}

test "envelope: ACK roundtrip" {
    var buf: [max_encoded_len]u8 = undefined;
    const e = Envelope{ .ack = .{ .msg_id = filled(16, 0xC1) } };
    const bytes = try encode(&buf, e);
    try testing.expectEqual(1 + 16, bytes.len);
    const back = try decode(bytes);
    try testing.expectEqualSlices(u8, &filled(16, 0xC1), &back.ack.msg_id);
}

test "envelope: FILE_ACK roundtrip" {
    var buf: [max_encoded_len]u8 = undefined;
    const e = Envelope{ .file_ack = .{ .file_id = @splat(0x6C), .got = 0xAABBCCDD } };
    const bytes = try encode(&buf, e);
    try testing.expectEqual(@as(usize, 1 + id_len + 4), bytes.len);
    try testing.expectEqual(@as(u8, 0x62), bytes[0]);
    // got u32 LE сразу после file_id
    try testing.expectEqualSlices(u8, &[_]u8{ 0xDD, 0xCC, 0xBB, 0xAA }, bytes[17..21]);

    const back = try decode(bytes);
    try testing.expectEqualSlices(u8, &@as([id_len]u8, @splat(0x6C)), &back.file_ack.file_id);
    try testing.expectEqual(@as(u32, 0xAABBCCDD), back.file_ack.got);
    try testing.expectError(error.Truncated, decode(bytes[0 .. bytes.len - 1]));
    var with_tail: [32]u8 = undefined;
    @memcpy(with_tail[0..bytes.len], bytes);
    with_tail[bytes.len] = 0;
    try testing.expectError(error.BadLen, decode(with_tail[0 .. bytes.len + 1]));
}

test "envelope: FILE_META/FILE_DATA roundtrip" {
    const fid: [16]u8 = filled(id_len, 0xAB);
    var sha: [32]u8 = undefined;
    @memset(&sha, 0x5C);
    const m: Envelope = .{ .file_meta = .{
        .file_id = fid,
        .name = "отчёт.pdf",
        .size = 12345,
        .sha = sha,
    } };
    var buf: [max_encoded_len]u8 = undefined;
    const enc = try encode(&buf, m);
    const back = try decode(enc);
    try testing.expectEqualSlices(u8, &fid, &back.file_meta.file_id);
    try testing.expectEqualStrings("отчёт.pdf", back.file_meta.name);
    try testing.expectEqual(@as(u32, 12345), back.file_meta.size);
    try testing.expectEqualSlices(u8, &sha, &back.file_meta.sha);

    var data: [4096]u8 = undefined;
    @memset(&data, 0x77);
    const d: Envelope = .{ .file_data = .{ .file_id = fid, .seq = 3, .data = &data } };
    const enc2 = try encode(&buf, d);
    const back2 = try decode(enc2);
    try testing.expectEqualSlices(u8, &fid, &back2.file_data.file_id);
    try testing.expectEqual(@as(u32, 3), back2.file_data.seq);
    try testing.expectEqualSlices(u8, &data, back2.file_data.data);

    // имя > max_file_name -> TooBig
    var long_name: [max_file_name + 1]u8 = undefined;
    @memset(&long_name, 'x');
    const bad: Envelope = .{ .file_meta = .{ .file_id = fid, .name = &long_name, .size = 1, .sha = sha } };
    try testing.expectError(error.TooBig, encode(&buf, bad));
}

// ------------------------------------------------------------------ SYNC

/// Тестовый хвост SYNC-партии: две записи
/// ([kind][mac 32][len 2][data] × 2, data = "abc" и ∅).
fn sampleSyncTail() [73]u8 {
    var tail: [73]u8 = @splat(0);
    tail[0] = 7; // kind
    @memset(tail[1..33][0..sync_mac_len], 0xA5);
    std.mem.writeInt(u16, tail[33..35], 3, .little);
    tail[35] = 'a';
    tail[36] = 'b';
    tail[37] = 'c';
    const off = 38; // начало второй записи
    tail[off + 0] = 8; // kind
    @memset(tail[off + 1 ..][0..sync_mac_len], 0x3C);
    // len 0, данных нет
    return tail;
}

test "SYNC: roundtrip и раскладка" {
    const tail = sampleSyncTail();
    const m: Envelope = .{ .sync = .{
        .batch_id = 0xDEADBEEF,
        .count = 2,
        .recs = &tail,
    } };
    var buf: [max_encoded_len]u8 = undefined;
    const enc = try encode(&buf, m);
    try testing.expectEqual(@as(usize, 1 + 4 + 1 + tail.len), enc.len);
    try testing.expectEqual(0x45, enc[0]);
    try testing.expectEqualSlices(u8, &.{ 0xEF, 0xBE, 0xAD, 0xDE }, enc[1..5]);
    try testing.expectEqual(@as(u8, 2), enc[5]);

    const back = try decode(enc);
    try testing.expectEqual(@as(u32, 0xDEADBEEF), back.sync.batch_id);
    try testing.expectEqual(@as(u8, 2), back.sync.count);
    try testing.expectEqualSlices(u8, &tail, back.sync.recs);

    var views: [max_sync_recs]SyncRecView = undefined;
    try testing.expectEqual(@as(usize, 2), try parseSyncRecs(back.sync.recs, back.sync.count, &views));
    try testing.expectEqual(@as(u8, 7), views[0].kind);
    try testing.expectEqualStrings("abc", views[0].data);
    try testing.expectEqual(@as(usize, 0), views[1].data.len);
}

test "SYNC: битая структура отбрасывается" {
    const tail = sampleSyncTail();
    var buf: [max_encoded_len]u8 = undefined;
    // 1) хвост обрезан
    {
        const m: Envelope = .{ .sync = .{ .batch_id = 1, .count = 2, .recs = tail[0 .. tail.len - 1] } };
        try testing.expectError(error.TooBig, encode(&buf, m));
    }
    // 2) count не совпадает с хвостом (записей меньше)
    {
        const m: Envelope = .{ .sync = .{ .batch_id = 1, .count = 3, .recs = &tail } };
        try testing.expectError(error.TooBig, encode(&buf, m));
    }
    // 3) лишний хвост после партии: строгий encode отказывает (хвост
    // обязан разбираться ровно на count записей — приемник не молчит,
    // отправитель тоже)
    {
        var big: [tail.len + 1]u8 = undefined;
        @memcpy(big[0..tail.len], &tail);
        big[tail.len] = 0;
        const m: Envelope = .{ .sync = .{ .batch_id = 1, .count = 2, .recs = &big } };
        try testing.expectError(error.TooBig, encode(&buf, m));
    }
    // 4) count > max_sync_recs
    {
        const m: Envelope = .{ .sync = .{ .batch_id = 1, .count = max_sync_recs + 1, .recs = &tail } };
        try testing.expectError(error.TooBig, encode(&buf, m));
    }
}

test "SYNC: payload записи больше max_sync_rec_data" {
    var data: [max_sync_rec_data + 1]u8 = undefined;
    @memset(&data, 1);
    var tail: [1 + sync_mac_len + 2 + max_sync_rec_data + 1]u8 = @splat(0);
    std.mem.writeInt(u16, tail[33..35], data.len, .little);
    @memcpy(tail[35..], &data);
    const m: Envelope = .{ .sync = .{ .batch_id = 1, .count = 1, .recs = &tail } };
    var buf: [max_encoded_len]u8 = undefined;
    try testing.expectError(error.TooBig, encode(&buf, m));
}

test "SYNC_ACK: roundtrip" {
    const m: Envelope = .{ .sync_ack = .{ .batch_id = 42 } };
    var buf: [16]u8 = undefined;
    const enc = try encode(&buf, m);
    try testing.expectEqualSlices(u8, &.{ 0x46, 42, 0, 0, 0 }, enc);
    const back = try decode(enc);
    try testing.expectEqual(@as(u32, 42), back.sync_ack.batch_id);
}
test "v6addr: roundtrip + encodedLen" {
    var v: V6Addr = .{
        .count = 2,
        .ips = .{
            .{ 0x20, 0x01, 0x0d, 0xb8 } ++ @as([12]u8, @splat(1)),
            .{ 0xfd, 0x00 } ++ @as([14]u8, @splat(2)),
        },
        .port = 7777,
    };
    const want_len = 1 + 1 + 2 * 16 + 2;
    try testing.expectEqual(want_len, encodedLen(.{ .v6addr = v }));
    var buf: [max_encoded_len]u8 = undefined;
    const wire = try encode(&buf, .{ .v6addr = v });
    try testing.expectEqual(want_len, wire.len);
    const back = try decode(wire);
    const q = back.v6addr;
    try testing.expectEqual(@as(u8, 2), q.count);
    try testing.expectEqualSlices(u8, &v.ips[0], &q.ips[0]);
    try testing.expectEqualSlices(u8, &v.ips[1], &q.ips[1]);
    try testing.expectEqual(@as(u16, 7777), q.port);
}

test "v6addr: битые кадры -> BadLen/Truncated" {
    // count = 0
    try testing.expectError(error.BadLen, decode(&[_]u8{ 0x48, 0 }));
    // count = 3 (лимит 2)
    try testing.expectError(error.BadLen, decode(&[_]u8{ 0x48, 3 }));
    // порт 0
    try testing.expectError(error.BadLen, decode(&[_]u8{ 0x48, 1 } ++ @as([16]u8, @splat(1)) ++ &[_]u8{ 0, 0 }));
    // усечён (нет порта)
    try testing.expectError(error.Truncated, decode(&[_]u8{ 0x48, 1 } ++ @as([16]u8, @splat(1))));
    // лишний байт хвоста
    try testing.expectError(error.BadLen, decode(&[_]u8{ 0x48, 1 } ++ @as([16]u8, @splat(1)) ++ &[_]u8{ 0x7f, 0x1e, 0 }));
    // encode: count вне лимита / порт 0
    var bad: V6Addr = .{ .count = 3, .ips = @splat(@splat(0)), .port = 7777 };
    var buf: [max_encoded_len]u8 = undefined;
    try testing.expectError(error.BadLen, encode(&buf, .{ .v6addr = bad }));
    bad.count = 1;
    bad.port = 0;
    try testing.expectError(error.BadLen, encode(&buf, .{ .v6addr = bad }));
}
