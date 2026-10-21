//! Тесты одноразовых ключей аудиовызова (crypto/call_keys.zig):
//! различие ключей по seq, детерминизм вывода HKDF.
//! Корень — шаг test-crypto (zig build test-crypto).
const std = @import("std");
const stille_messenger = @import("stille-messenger");

const call_keys = stille_messenger.crypto.call_keys;
const keyFor = call_keys.keyFor;

test "call_keys: разные seq -> разные ключи" {
    const secret: [32]u8 = @splat(9);
    const k0 = keyFor(secret, 0);
    const k1 = keyFor(secret, 1);
    const kmax = keyFor(secret, 0xffffffff);
    try std.testing.expect(!std.mem.eql(u8, &k0, &k1));
    try std.testing.expect(!std.mem.eql(u8, &k0, &kmax));
    try std.testing.expect(!std.mem.eql(u8, &k1, &kmax));
}

test "call_keys: детерминизм" {
    const secret: [32]u8 = @splat(9);
    const a = keyFor(secret, 12345);
    const b = keyFor(secret, 12345);
    try std.testing.expectEqualSlices(u8, &a, &b);

    const secret2: [32]u8 = @splat(10);
    const c = keyFor(secret2, 12345);
    try std.testing.expect(!std.mem.eql(u8, &a, &c));
}
