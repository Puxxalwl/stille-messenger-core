//! Тесты паддинга кадров (crypto/pad.zig): roundtrip по классам размеров,
//! случайный довесок, TooShort/BadLen.
//! Корень — шаг test-crypto (zig build test-crypto).
const std = @import("std");
const stille_messenger = @import("stille-messenger");

const pad = stille_messenger.crypto.pad;
const buckets = pad.buckets;
const max_payload = pad.max_payload;
const bucketFor = pad.bucketFor;
const padTo = pad.padTo;
const unpad = pad.unpad;

test "pad: roundtrip и границы классов" {
    const io = std.testing.io;
    var buf: [buckets[buckets.len - 1]]u8 = undefined;

    inline for (buckets) |b| {
        // payload занимает весь класс без заголовка: минимальный запас
        var payload: [b - 2]u8 = undefined;
        @memset(&payload, 0xAB);
        const padded = try padTo(&buf, &payload, io, 0);
        try std.testing.expectEqual(@as(usize, b), padded.len);

        const back = try unpad(padded);
        try std.testing.expectEqualSlices(u8, &payload, back);
    }
}

test "pad: случайные размеры и довесок" {
    const io = std.testing.io;
    var buf: [buckets[buckets.len - 1]]u8 = undefined;

    const sizes = [_]usize{ 0, 1, 2, 100, 126, 127, 200, 400, 900, 4000, 16000, max_payload };
    for (sizes) |n| {
        var payload: [max_payload]u8 = undefined;
        @memset(payload[0..n], 0x5A);
        const padded = try padTo(&buf, payload[0..n], io, 77);
        const bucket = bucketFor(2 + n).?;
        try std.testing.expectEqual(bucket, padded.len);
        try std.testing.expectEqualSlices(u8, payload[0..n], try unpad(padded));
    }

    // без довеска хвост кадра нулевой
    const padded = try padTo(&buf, "abc", io, 0);
    for (padded[5..]) |byte| try std.testing.expectEqual(@as(u8, 0), byte);

    // довесок ограничен 1/16 класса
    const padded2 = try padTo(&buf, "abc", io, 100000);
    try std.testing.expectEqual(@as(usize, 128), padded2.len);
    try std.testing.expectEqualSlices(u8, "abc", try unpad(padded2));
}

test "pad: TooShort" {
    const io = std.testing.io;
    var big: [buckets[buckets.len - 1]]u8 = undefined;

    // payload больше максимального класса
    var over: [max_payload + 1]u8 = undefined;
    try std.testing.expectError(error.TooShort, padTo(&big, &over, io, 0));

    // буфер вывода меньше класса
    var small: [127]u8 = undefined;
    try std.testing.expectError(error.TooShort, padTo(&small, "abc", io, 0));
}

test "pad: порча заголовка длины -> BadLen" {
    const io = std.testing.io;
    var buf: [256]u8 = undefined;

    const padded = try padTo(&buf, "hello", io, 0);
    try std.testing.expectEqualSlices(u8, "hello", try unpad(padded));

    var broken: [128]u8 = undefined;
    @memcpy(&broken, padded);
    std.mem.writeInt(u16, broken[0..2], 500, .little); // 500 + 2 > 128
    try std.testing.expectError(error.BadLen, unpad(&broken));
}

test "pad: unpad TooShort" {
    try std.testing.expectError(error.TooShort, unpad(&[_]u8{}));
    try std.testing.expectError(error.TooShort, unpad(&[_]u8{1}));
}
