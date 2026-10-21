//! Тесты симметричного рэтчета (crypto/ratchet.zig): эволюция ключей и
//! счётчиков, peek/commit приёма, зеркальность сторон, dhStep.
//! Корень — шаг test-crypto (zig build test-crypto).
const std = @import("std");
const stille_messenger = @import("stille-messenger");

const ratchet = stille_messenger.crypto.ratchet;
const Ratchet = ratchet.Ratchet;
// Приватный алиас исходного файла (см. ratchet.zig), воссоздан локально:
// тесты выводят DH-паблики напрямую из std.crypto.
const X25519 = std.crypto.dh.X25519;

test "ratchet: эволюция ключей и счётчиков" {
    var r = Ratchet.init(@splat(1), @splat(2));

    var k0: [32]u8 = undefined;
    var k1: [32]u8 = undefined;
    var k2: [32]u8 = undefined;
    const c0 = r.stepSend(&k0);
    const c1 = r.stepSend(&k1);
    const c2 = r.stepSend(&k2);

    try std.testing.expectEqual(@as(u64, 0), c0);
    try std.testing.expectEqual(@as(u64, 1), c1);
    try std.testing.expectEqual(@as(u64, 2), c2);
    try std.testing.expect(!std.mem.eql(u8, &k0, &k1));
    try std.testing.expect(!std.mem.eql(u8, &k1, &k2));
    try std.testing.expect(!std.mem.eql(u8, &k0, &k2));

    // цепочка приёма независима от цепочки отправки
    var rk0: [32]u8 = undefined;
    try std.testing.expectEqual(@as(u64, 0), r.peekRecv(&rk0));
    r.commitRecv();
    try std.testing.expect(!std.mem.eql(u8, &k0, &rk0));
}

test "ratchet: peekRecv не сдвигает цепочку до commitRecv" {
    var a = Ratchet.init(@splat(3), @splat(4));

    // два peek без commit: один и тот же ключ и счётчик (кадр можно
    // попытаться расшифровать повторно, цепочка не поехала)
    var k1: [32]u8 = undefined;
    var k2: [32]u8 = undefined;
    try std.testing.expectEqual(@as(u64, 0), a.peekRecv(&k1));
    try std.testing.expectEqual(@as(u64, 0), a.peekRecv(&k2));
    try std.testing.expectEqualSlices(u8, &k1, &k2);

    // «расшифровка не удалась» — цепочка не сдвинута, следующий кадр
    // выводится из того же состояния
    var k3: [32]u8 = undefined;
    try std.testing.expectEqual(@as(u64, 0), a.peekRecv(&k3));
    try std.testing.expectEqualSlices(u8, &k1, &k3);

    // успешная расшифровка: commit сдвигает цепочку и счётчик
    a.commitRecv();
    var k4: [32]u8 = undefined;
    try std.testing.expectEqual(@as(u64, 1), a.peekRecv(&k4));
    try std.testing.expect(!std.mem.eql(u8, &k1, &k4));
    // счётчик отправки не тронут: peek/commit не влияют на исходящие
    try std.testing.expectEqual(@as(u64, 0), a.send_counter);
}

test "ratchet: peekRecv+commitRecv зеркальны stepSend" {
    var a = Ratchet.init(@splat(3), @splat(4));
    var b = Ratchet.init(@splat(4), @splat(3)); // встречные цепочки

    var mk: [32]u8 = undefined;
    var rk: [32]u8 = undefined;
    const sc = a.stepSend(&mk);
    const rc = b.peekRecv(&rk);
    b.commitRecv();

    try std.testing.expectEqual(sc, rc);
    try std.testing.expectEqualSlices(u8, &mk, &rk);

    var mk2: [32]u8 = undefined;
    var rk2: [32]u8 = undefined;
    const sc2 = a.stepSend(&mk2);
    const rc2 = b.peekRecv(&rk2);
    b.commitRecv();
    try std.testing.expectEqual(sc2, rc2);
    try std.testing.expectEqualSlices(u8, &mk2, &rk2);
    try std.testing.expect(!std.mem.eql(u8, &mk, &mk2));
}

test "ratchet: зеркальность сторон после dhStep" {
    var sk_a: [32]u8 = undefined;
    var sk_b: [32]u8 = undefined;
    for (&sk_a, 0..) |*byte, i| byte.* = @truncate(i *% 5 +% 1);
    for (&sk_b, 0..) |*byte, i| byte.* = @truncate(i *% 9 +% 7);

    const pk_a = X25519.recoverPublicKey(sk_a);
    const pk_b = X25519.recoverPublicKey(sk_b);

    var a = Ratchet.init(@splat(1), @splat(1));
    var b = Ratchet.init(@splat(2), @splat(2));

    try a.dhStep(pk_b, sk_a);
    try b.dhStep(pk_a, sk_b);
    // эпоха синхронно +1 у обеих сторон
    try std.testing.expectEqual(@as(u16, 1), a.epoch);
    try std.testing.expectEqual(@as(u16, 1), b.epoch);

    // у обеих сторон одинаковые встречные цепочки
    try std.testing.expectEqualSlices(u8, &a.chain_send, &b.chain_recv);
    try std.testing.expectEqualSlices(u8, &a.chain_recv, &b.chain_send);
    try std.testing.expectEqual(@as(u64, 0), a.send_counter);
    try std.testing.expectEqual(@as(u64, 0), b.recv_counter);

    // ключи сообщений сходятся после dhStep
    var mk: [32]u8 = undefined;
    var rk: [32]u8 = undefined;
    const sc = a.stepSend(&mk);
    const rc = b.peekRecv(&rk);
    b.commitRecv();
    try std.testing.expectEqual(sc, rc);
    try std.testing.expectEqualSlices(u8, &mk, &rk);
}

test "ratchet: цепочки после dhStep отличаются от прежних" {
    const sk_a: [32]u8 = @splat(1);
    const sk_b: [32]u8 = @splat(2);
    const pk_b = X25519.recoverPublicKey(sk_b);

    var a = Ratchet.init(@splat(1), @splat(1));
    const old_send = a.chain_send;
    try a.dhStep(pk_b, sk_a);
    try std.testing.expect(!std.mem.eql(u8, &old_send, &a.chain_send));
    const after_first = a.chain_send;

    // повторный dhStep с новой удалённой парой -> снова новые цепочки,
    // счётчики снова с нуля
    const sk_c = [_]u8{9} ++ @as([31]u8, @splat(4));
    const pk_c = X25519.recoverPublicKey(sk_c);
    try a.dhStep(pk_c, sk_a);
    try std.testing.expect(!std.mem.eql(u8, &after_first, &a.chain_send));
    try std.testing.expect(!std.mem.eql(u8, &after_first, &a.chain_recv));
    try std.testing.expectEqual(@as(u64, 0), a.send_counter);
    try std.testing.expectEqual(@as(u64, 0), a.recv_counter);
}

test "ratchet: вырожденный ключ -> BadRemoteKey" {
    var a = Ratchet.init(@splat(1), @splat(1));
    const zero_pub: [32]u8 = @splat(0);
    try std.testing.expectError(error.BadRemoteKey, a.dhStep(zero_pub, @splat(3)));
}
