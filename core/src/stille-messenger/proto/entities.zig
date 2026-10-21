//! Entities форматирования TEXT: типы, валидация, кодирование хвоста.
//! Выделено из envelope.zig (единая ответственность: контракт entities —
//! счётчик + записи; валидация диапазонов/сортировки/правил value).
//! Порядок байтов и значения кодов — контракт провода v4 (не менять).
const std = @import("std");
const codec = @import("codec.zig");

/// Максимум entities форматирования на одно TEXT-сообщение.
pub const max_text_entities = 32;
/// Максимум длины value одной entity (совпадает с u8-длиной на проводе).
pub const max_entity_value = 255;
/// Максимум длины хвоста entities в TEXT: счётчик + записи.
pub const max_text_tail = 1 + max_text_entities * (6 + max_entity_value);

/// Тип форматирования TEXT. Значения — контракт провода v4: новые типы
/// требуют бампа версии протокола (приём неизвестного кода = ошибка).
pub const EntityKind = enum(u8) {
    bold = 1,
    italic = 2,
    underline = 3,
    strikethrough = 4,
    spoiler = 5,
    /// Инлайн-код (`...`).
    code = 6,
    /// Блок кода; value — необязательный тег языка.
    pre = 7,
    /// Ссылка; value — URL (обязателен, ≤ max_entity_value).
    link = 8,
};

/// Одна entity форматирования: диапазон тела + тип + значение (стиль
/// Telegram MessageEntity). offset/len — БАЙТЫ UTF-8 в body (не code
/// points): в бинарном протоколе однозначно и без пересчёта; клиент при
/// рендере обязан резать по границам символов.
pub const TextEntity = struct {
    kind: EntityKind,
    /// Байтовое смещение начала в body.
    offset: u16,
    /// Длина диапазона в байтах (≥ 1).
    len: u16,
    /// Значение по kind: link — URL (обязателен), pre — язык (опционален),
    /// остальные — пусто. ≤ max_entity_value.
    value: []const u8 = &.{},
};

/// Ошибки entities: структура хвоста и правила (границы, сортировка,
/// соответствие value типу).
pub const EntitiesError = error{
    /// Хвост обрезан (не хватает байтов записи/value).
    Truncated,
    /// Лишние байты после последней записи.
    BadLen,
    /// Больше max_text_entities записей.
    TooMany,
    /// value длиннее max_entity_value.
    TooLong,
    /// len == 0 или offset+len выходит за body.
    OutOfRange,
    /// Записи не отсортированы по offset.
    Unsorted,
    /// value не соответствует kind (пустой URL, value у bold и т.п.).
    BadValue,
    /// Неизвестный код типа.
    BadKind,
};

/// Проверить типизированные entities против тела длиной body_len:
/// лимиты, границы, сортировку по offset, правила value. Пересечения
/// диапазонов (bold+italic на одном куске) разрешены. Вход API и движок
/// обязаны прогонять это до отправки; decode валидирует провод сам.
pub fn validateEntities(ents: []const TextEntity, body_len: usize) EntitiesError!void {
    if (ents.len > max_text_entities) return error.TooMany;
    var last_offset: ?u16 = null;
    for (ents) |e| {
        if (e.value.len > max_entity_value) return error.TooLong;
        if (e.len == 0) return error.OutOfRange;
        if (@as(usize, e.offset) + e.len > body_len) return error.OutOfRange;
        if (last_offset) |lo| {
            if (e.offset < lo) return error.Unsorted;
        }
        last_offset = e.offset;
        switch (e.kind) {
            .link => if (e.value.len == 0) return error.BadValue,
            .pre => {},
            .bold, .italic, .underline, .strikethrough, .spoiler, .code => if (e.value.len != 0) return error.BadValue,
        }
    }
}

/// Сериализовать entities в канонический хвост (провод TEXT, запись лога,
/// кадр API — один и тот же формат):
/// [count u8] × {[kind u8][offset u16][len u16][value_len u8][value]}.
/// Валидирует перед записью; NoSpace — буфер короче. Возвращает срез buf.
pub fn encodeEntitiesTail(buf: []u8, ents: []const TextEntity, body_len: usize) (codec.Writer.Error || EntitiesError)![]const u8 {
    try validateEntities(ents, body_len);
    var w = codec.Writer.init(buf);
    try w.put(@intCast(ents.len));
    for (ents) |e| {
        try w.put(@backingInt(e.kind));
        try w.putInt(u16, e.offset);
        try w.putInt(u16, e.len);
        try w.put(@intCast(e.value.len));
        try w.putFixed(e.value);
    }
    return w.buf[0..w.pos];
}

/// Разобрать и провалидировать хвост entities; весь `bytes` обязан быть
/// потреблён (лишний хвост — BadLen). Заполняет `out` (если задан):
/// не меньше count записей; value — срезы в `bytes`. Возвращает count.
pub fn parseEntities(bytes: []const u8, body_len: usize, out: ?[]TextEntity) EntitiesError!usize {
    if (bytes.len < 1) return error.Truncated;
    const count: usize = bytes[0];
    if (count > max_text_entities) return error.TooMany;
    var pos: usize = 1;
    var last_offset: ?u16 = null;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        if (bytes.len - pos < 6) return error.Truncated;
        const kind = std.enums.fromInt(EntityKind, bytes[pos]) orelse return error.BadKind;
        const offset = std.mem.readInt(u16, bytes[pos + 1 ..][0..2], .little);
        const len = std.mem.readInt(u16, bytes[pos + 3 ..][0..2], .little);
        const vlen: usize = bytes[pos + 5];
        pos += 6;
        if (vlen > max_entity_value) return error.TooLong;
        if (bytes.len - pos < vlen) return error.Truncated;
        const value = bytes[pos .. pos + vlen];
        pos += vlen;
        if (len == 0) return error.OutOfRange;
        if (@as(usize, offset) + len > body_len) return error.OutOfRange;
        if (last_offset) |lo| {
            if (offset < lo) return error.Unsorted;
        }
        last_offset = offset;
        switch (kind) {
            .link => if (vlen == 0) return error.BadValue,
            .pre => {},
            .bold, .italic, .underline, .strikethrough, .spoiler, .code => if (vlen != 0) return error.BadValue,
        }
        if (out) |o| o[i] = .{ .kind = kind, .offset = offset, .len = len, .value = value };
    }
    if (pos != bytes.len) return error.BadLen;
    return count;
}
