//! Тесты AEAD (crypto/aead.zig): roundtrip ChaCha20-Poly1305, порча
//! шифротекста/тега/AD/ключа, раскладка nonceFor, TooShort.
//! Корень — шаг test-crypto (zig build test-crypto).
const std = @import("std");
const stille_messenger = @import("stille-messenger");

const aead = stille_messenger.crypto.aead;
const nonceFor = aead.nonceFor;
const seal = aead.seal;
const open = aead.open;
const tag_length = aead.tag_length;

test "aead: roundtrip" {
    const key: [32]u8 = @splat(7);
    const nonce = nonceFor(42);
    const plain = "hello stille-messenger";

    var buf: [plain.len + tag_length]u8 = undefined;
    seal(&buf, plain, key, nonce, "ad");

    var out: [plain.len]u8 = undefined;
    try open(&out, &buf, key, nonce, "ad");
    try std.testing.expectEqualSlices(u8, plain, &out);
}

test "aead: битый байт -> Tampered" {
    const key: [32]u8 = @splat(7);
    const nonce = nonceFor(1);
    const plain = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };

    var buf: [plain.len + tag_length]u8 = undefined;
    seal(&buf, &plain, key, nonce, "ad");

    var out: [plain.len]u8 = undefined;

    // порча шифротекста
    buf[3] ^= 0x01;
    try std.testing.expectError(error.Tampered, open(&out, &buf, key, nonce, "ad"));

    // порча тега
    buf[3] ^= 0x01;
    buf[buf.len - 1] ^= 0x80;
    try std.testing.expectError(error.Tampered, open(&out, &buf, key, nonce, "ad"));
}

test "aead: другой AD -> Tampered" {
    const key: [32]u8 = @splat(7);
    const nonce = nonceFor(2);
    const plain = "payload";

    var buf: [plain.len + tag_length]u8 = undefined;
    seal(&buf, plain, key, nonce, "header-a");

    var out: [plain.len]u8 = undefined;
    try std.testing.expectError(error.Tampered, open(&out, &buf, key, nonce, "header-b"));
}

test "aead: чужой ключ -> Tampered" {
    const key: [32]u8 = @splat(7);
    const other_key: [32]u8 = @splat(8);
    const nonce = nonceFor(3);
    const plain = "payload";

    var buf: [plain.len + tag_length]u8 = undefined;
    seal(&buf, plain, key, nonce, "");

    var out: [plain.len]u8 = undefined;
    try std.testing.expectError(error.Tampered, open(&out, &buf, other_key, nonce, ""));
}

test "aead: nonceFor раскладка счётчика" {
    const n = nonceFor(1);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0 }, n[0..4]);
    try std.testing.expectEqual(@as(u64, 1), std.mem.readInt(u64, n[4..12], .little));
    const big = nonceFor(0x0102030405060708);
    try std.testing.expectEqual(@as(u64, 0x0102030405060708), std.mem.readInt(u64, big[4..12], .little));
}

test "aead: TooShort" {
    const key: [32]u8 = @splat(7);
    const nonce = nonceFor(4);

    // box короче тега
    var out: [32]u8 = undefined;
    try std.testing.expectError(error.TooShort, open(&out, &[_]u8{ 9, 9, 9, 9, 9, 9, 9, 9 }, key, nonce, ""));

    // нормальный box, но буфер вывода мал
    const plain = [_]u8{ 1, 2, 3 };
    var buf: [plain.len + tag_length]u8 = undefined;
    seal(&buf, &plain, key, nonce, "");
    var small: [2]u8 = undefined;
    try std.testing.expectError(error.TooShort, open(&small, &buf, key, nonce, ""));
}
