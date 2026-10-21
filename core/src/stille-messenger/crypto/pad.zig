//! Паддинг длины кадров: класс размеров выбирается из buckets, к payload
//! добавляется случайный довесок (до 1/16 класса), остаток забивается нулями.
//! Раскладка кадра: [u16 payload_len LE][payload][random pad][zero pad].

const std = @import("std");

/// Ошибки: TooShort — не хватает буфера или payload вне классов,
/// BadLen — заголовок длины не согласован с данными.
pub const Error = error{ TooShort, BadLen };

/// Классы размеров кадра. Таблица общая с net/obfuscate.zig (синхронно менять).
/// Класса 65536 нет: длина кадра на проводе — u16, запас обязан быть явным.
pub const buckets = [_]usize{ 128, 256, 512, 1024, 4096, 16384 };

/// Максимальный размер payload: кадр с заголовком u16 обязан влезть в класс.
pub const max_payload = buckets[buckets.len - 1] - 2;

/// Возвращает минимальный класс >= `frame` или null, если frame больше последнего.
pub fn bucketFor(frame: usize) ?usize {
    for (buckets) |b| {
        if (b >= frame) return b;
    }
    return null;
}

/// Пишет кадр [u16 payload_len LE][payload][random pad][zero pad] в `out`
/// и возвращает срез длиной ровно в выбранный класс. `extra_rand_bytes`
/// ограничивает случайный довесок сверху: не более 1/16 класса и не более
/// свободного места класса. Случайность берётся из `io`.
pub fn padTo(out: []u8, payload: []const u8, io: std.Io, extra_rand_bytes: usize) Error![]u8 {
    if (payload.len > max_payload) return error.TooShort;
    const frame = 2 + payload.len;
    const bucket = bucketFor(frame) orelse return error.TooShort;
    if (out.len < bucket) return error.TooShort;

    var extra = extra_rand_bytes;
    const max_extra = bucket / 16;
    if (extra > max_extra) extra = max_extra;
    if (extra > bucket - frame) extra = bucket - frame;

    std.mem.writeInt(u16, out[0..2], @intCast(payload.len), .little);
    @memcpy(out[2 .. 2 + payload.len], payload);
    io.random(out[frame .. frame + extra]);
    @memset(out[frame + extra .. bucket], 0);
    return out[0..bucket];
}

/// Извлекает payload из паддированного кадра; согласованный заголовок длины
/// обязателен, иначе BadLen.
pub fn unpad(buf: []const u8) Error![]const u8 {
    if (buf.len < 2) return error.TooShort;
    const len: usize = std.mem.readInt(u16, buf[0..2], .little);
    if (2 + len > buf.len) return error.BadLen;
    return buf[2 .. 2 + len];
}
