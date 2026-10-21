//! Тесты гибридного рукопожатия (crypto/handshake.zig): полный обмен
//! m1/m2/m3, зеркальные ключи, детерминизм, порча полей, PQ-подмены.
//! Корень — шаг test-crypto (zig build test-crypto).
const std = @import("std");
const stille_messenger = @import("stille-messenger");

const handshake = stille_messenger.crypto.handshake;
// Приватные алиасы исходного файла (см. handshake.zig): тесты звали их
// напрямую; здесь они ведут на публичные модули библиотеки.
const aead = stille_messenger.crypto.aead;
const identity = stille_messenger.crypto.identity;

const SessionKeys = handshake.SessionKeys;
const Initiator = handshake.Initiator;
const Responder = handshake.Responder;
const m1_len = handshake.m1_len;
const m2_len = handshake.m2_len;
const m3_len = handshake.m3_len;

/// Фиксированные сиды: полный рукопожатие детерминистичен.
const seed_i = 0xA5;
const seed_r = 0x5A;
const eph_i_seed: [32]u8 = @splat(0x11);
const eph_r_seed: [32]u8 = @splat(0x22);

fn testIdentity(fill: u8) !identity.Identity {
    const seed: [32]u8 = @splat(fill);
    return identity.Identity.fromSeed(seed);
}

fn runHandshake() !struct { init_keys: SessionKeys, resp_keys: SessionKeys, m1: [m1_len]u8, m2: [m2_len]u8, m3: [m3_len]u8 } {
    var id_i = try testIdentity(seed_i);
    defer id_i.deinit();
    var id_r = try testIdentity(seed_r);
    defer id_r.deinit();

    var m1: [m1_len]u8 = undefined;
    var m2: [m2_len]u8 = undefined;
    var m3: [m3_len]u8 = undefined;

    var init = try Initiator.start(&m1, &id_i, eph_i_seed);
    var resp = try Responder.recv1(&m2, &id_r, &m1, eph_r_seed);
    const init_keys = try init.recv2(&m3, &m2, id_r.sign_public, id_r.enc_public);
    const resp_keys = try resp.recv3(&m3, id_i.sign_public, id_i.enc_public);

    return .{ .init_keys = init_keys, .resp_keys = resp_keys, .m1 = m1, .m2 = m2, .m3 = m3 };
}

test "handshake: полный рукопожатие, ключи зеркальны" {
    const hs = try runHandshake();

    try std.testing.expectEqualSlices(u8, &hs.init_keys.send_key, &hs.resp_keys.recv_key);
    try std.testing.expectEqualSlices(u8, &hs.init_keys.recv_key, &hs.resp_keys.send_key);
    try std.testing.expectEqualSlices(u8, &hs.init_keys.transcript, &hs.resp_keys.transcript);
    try std.testing.expect(!std.mem.eql(u8, &hs.init_keys.send_key, &hs.init_keys.recv_key));
}

test "handshake: трафик сессионными ключами" {
    const hs = try runHandshake();
    const plain = "первый кадр";
    const nonce = aead.nonceFor(0);

    var buf: [plain.len + aead.tag_length]u8 = undefined;
    aead.seal(&buf, plain, hs.init_keys.send_key, nonce, &hs.init_keys.transcript);

    var out: [plain.len]u8 = undefined;
    try aead.open(&out, &buf, hs.resp_keys.recv_key, nonce, &hs.resp_keys.transcript);
    try std.testing.expectEqualSlices(u8, plain, &out);
}

test "handshake: детерминизм при тех же сидах" {
    const a = try runHandshake();
    const b = try runHandshake();
    try std.testing.expectEqualSlices(u8, &a.m1, &b.m1);
    try std.testing.expectEqualSlices(u8, &a.m2, &b.m2);
    try std.testing.expectEqualSlices(u8, &a.m3, &b.m3);
    try std.testing.expectEqualSlices(u8, &a.init_keys.send_key, &b.init_keys.send_key);
    try std.testing.expectEqualSlices(u8, &a.init_keys.recv_key, &b.init_keys.recv_key);
    try std.testing.expectEqualSlices(u8, &a.init_keys.transcript, &b.init_keys.transcript);

    // другие эфемеральные сиды -> другие ключи при тех же личностях
    var id_i = try testIdentity(seed_i);
    defer id_i.deinit();
    var id_r = try testIdentity(seed_r);
    defer id_r.deinit();

    var m1a: [m1_len]u8 = undefined;
    var m1b: [m1_len]u8 = undefined;
    var m2a: [m2_len]u8 = undefined;
    var m2b: [m2_len]u8 = undefined;
    var m3a: [m3_len]u8 = undefined;
    var m3b: [m3_len]u8 = undefined;

    const eph_alt: [32]u8 = @splat(0x33);
    var ia = try Initiator.start(&m1a, &id_i, eph_i_seed);
    var ra = try Responder.recv1(&m2a, &id_r, &m1a, eph_r_seed);
    const ka = try ia.recv2(&m3a, &m2a, id_r.sign_public, id_r.enc_public);
    _ = try ra.recv3(&m3a, id_i.sign_public, id_i.enc_public);

    var ib = try Initiator.start(&m1b, &id_i, eph_alt);
    var rb = try Responder.recv1(&m2b, &id_r, &m1b, eph_alt);
    const kb = try ib.recv2(&m3b, &m2b, id_r.sign_public, id_r.enc_public);
    _ = try rb.recv3(&m3b, id_i.sign_public, id_i.enc_public);

    try std.testing.expect(!std.mem.eql(u8, &ka.send_key, &kb.send_key));
    try std.testing.expect(!std.mem.eql(u8, &ka.transcript, &kb.transcript));
}

test "handshake: битый байт в m2 -> Tampered" {
    var id_i = try testIdentity(seed_i);
    defer id_i.deinit();
    var id_r = try testIdentity(seed_r);
    defer id_r.deinit();

    var m1: [m1_len]u8 = undefined;
    var m2: [m2_len]u8 = undefined;
    var m3: [m3_len]u8 = undefined;

    var init = try Initiator.start(&m1, &id_i, eph_i_seed);
    var resp = try Responder.recv1(&m2, &id_r, &m1, eph_r_seed);
    _ = &resp;

    // порча шифротекста box1
    m2[m2.len - 1] ^= 0x01;
    try std.testing.expectError(error.Tampered, init.recv2(&m3, &m2, id_r.sign_public, id_r.enc_public));

    // порча e2_pub -> другой ee -> box1 не открывается
    m2[m2.len - 1] ^= 0x01;
    m2[0] ^= 0x01;
    try std.testing.expectError(error.Tampered, init.recv2(&m3, &m2, id_r.sign_public, id_r.enc_public));
}

test "handshake: чужой sign_pk у инициатора -> BadSignature" {
    var id_i = try testIdentity(seed_i);
    defer id_i.deinit();
    var id_r = try testIdentity(seed_r);
    defer id_r.deinit();
    var id_x = try testIdentity(0xEE);
    defer id_x.deinit();

    var m1: [m1_len]u8 = undefined;
    var m2: [m2_len]u8 = undefined;
    var m3: [m3_len]u8 = undefined;

    var init = try Initiator.start(&m1, &id_i, eph_i_seed);
    var resp = try Responder.recv1(&m2, &id_r, &m1, eph_r_seed);
    _ = &resp;

    // инициатор сверяет sig_r не с тем ключом
    try std.testing.expectError(error.BadSignature, init.recv2(&m3, &m2, id_x.sign_public, id_r.enc_public));
}

test "handshake: подмена sign_pk у ответчика -> BadSignature" {
    var id_i = try testIdentity(seed_i);
    defer id_i.deinit();
    var id_r = try testIdentity(seed_r);
    defer id_r.deinit();
    var id_x = try testIdentity(0x77);
    defer id_x.deinit();

    var m1: [m1_len]u8 = undefined;
    var m2: [m2_len]u8 = undefined;
    var m3: [m3_len]u8 = undefined;

    var init = try Initiator.start(&m1, &id_i, eph_i_seed);
    var resp = try Responder.recv1(&m2, &id_r, &m1, eph_r_seed);
    const keys = try init.recv2(&m3, &m2, id_r.sign_public, id_r.enc_public);

    // ответчик сверяет sig_i не с тем ключом
    try std.testing.expectError(error.BadSignature, resp.recv3(&m3, id_x.sign_public, id_i.enc_public));

    // контроль: с правильным ключом всё проходит
    var init2 = try Initiator.start(&m1, &id_i, eph_i_seed);
    var resp2 = try Responder.recv1(&m2, &id_r, &m1, eph_r_seed);
    const keys2 = try init2.recv2(&m3, &m2, id_r.sign_public, id_r.enc_public);
    const keys3 = try resp2.recv3(&m3, id_i.sign_public, id_i.enc_public);
    try std.testing.expectEqualSlices(u8, &keys.send_key, &keys2.send_key);
    try std.testing.expectEqualSlices(u8, &keys3.send_key, &keys.recv_key);
}

test "handshake: BadLength" {
    var id_i = try testIdentity(seed_i);
    defer id_i.deinit();
    var id_r = try testIdentity(seed_r);
    defer id_r.deinit();

    var m1: [m1_len]u8 = undefined;
    var m2: [m2_len]u8 = undefined;
    var m3: [m3_len]u8 = undefined;

    try std.testing.expectError(error.BadLength, Responder.recv1(&m2, &id_r, m1[0 .. m1.len - 1], eph_r_seed));

    var init = try Initiator.start(&m1, &id_i, eph_i_seed);
    _ = try Responder.recv1(&m2, &id_r, &m1, eph_r_seed);
    try std.testing.expectError(error.BadLength, init.recv2(&m3, m2[0 .. m2.len - 1], id_r.sign_public, id_r.enc_public));

    var resp = try Responder.recv1(&m2, &id_r, &m1, eph_r_seed);
    _ = try init.recv2(&m3, &m2, id_r.sign_public, id_r.enc_public);
    try std.testing.expectError(error.BadLength, resp.recv3(m3[0 .. m3.len - 2], id_i.sign_public, id_i.enc_public));
}

test "handshake: чужая статика в боксе -> KeyMismatch" {
    var id_i = try testIdentity(seed_i);
    defer id_i.deinit();
    var id_r = try testIdentity(seed_r);
    defer id_r.deinit();
    var id_x = try testIdentity(0xEE);
    defer id_x.deinit();

    var m1: [m1_len]u8 = undefined;
    var m2: [m2_len]u8 = undefined;
    var m3: [m3_len]u8 = undefined;

    var init = try Initiator.start(&m1, &id_i, eph_i_seed);
    var resp = try Responder.recv1(&m2, &id_r, &m1, eph_r_seed);

    // инициатор ждёт статику id_x, а пришла id_r
    try std.testing.expectError(error.KeyMismatch, init.recv2(&m3, &m2, id_r.sign_public, id_x.enc_public));

    // контрольный m3 (валидный путь), затем ответчик ждёт статику id_x,
    // а в m3 — id_i
    var init2 = try Initiator.start(&m1, &id_i, eph_i_seed);
    _ = try init2.recv2(&m3, &m2, id_r.sign_public, id_r.enc_public);
    try std.testing.expectError(error.KeyMismatch, resp.recv3(&m3, id_i.sign_public, id_x.enc_public));

    // null (pending-join): сверка не делается, всё проходит
    var resp2 = try Responder.recv1(&m2, &id_r, &m1, eph_r_seed);
    _ = try resp2.recv3(&m3, null, null);
}

test "handshake: PQ — подмена mlkem_pk в m1 -> Tampered" {
    var id_i = try testIdentity(seed_i);
    defer id_i.deinit();
    var id_r = try testIdentity(seed_r);
    defer id_r.deinit();

    var m1: [m1_len]u8 = undefined;
    var m2: [m2_len]u8 = undefined;
    var m3: [m3_len]u8 = undefined;

    var init = try Initiator.start(&m1, &id_i, eph_i_seed);
    // подмена последнего байта mlkem_pk (область rho: кодирование
    // остаётся каноничным, но матрица/шифротекст меняются)
    m1[m1.len - 1] ^= 0x01;
    var resp = try Responder.recv1(&m2, &id_r, &m1, eph_r_seed);
    _ = &resp;

    // транскрипты сторон уже разошлись (h1 = H(h0||m1)): box1 не открывается
    try std.testing.expectError(error.Tampered, init.recv2(&m3, &m2, id_r.sign_public, id_r.enc_public));
}

test "handshake: PQ — подмена mlkem_ct в m2 меняет ключи, m3 не открывается" {
    var id_i = try testIdentity(seed_i);
    defer id_i.deinit();
    var id_r = try testIdentity(seed_r);
    defer id_r.deinit();

    var m1: [m1_len]u8 = undefined;
    var m2: [m2_len]u8 = undefined;
    var m3: [m3_len]u8 = undefined;

    var init = try Initiator.start(&m1, &id_i, eph_i_seed);
    var resp = try Responder.recv1(&m2, &id_r, &m1, eph_r_seed);

    // подмена байта ВНУТРИ mlkem_ct (box1 не тронут): box1 у инициатора
    // всё ещё открывается (k1 не зависит от KEM), но ML-KEM-деинкапсуляция
    // даёт другой секрет -> ck расходится -> k2 другой -> m3 у ответчика
    // не открывается. Это и есть PQ-аутентификация ciphertext через
    // расписание ключей.
    m2[32 + 64] ^= 0x01;
    _ = try init.recv2(&m3, &m2, id_r.sign_public, id_r.enc_public);
    try std.testing.expectError(error.Tampered, resp.recv3(&m3, id_i.sign_public, id_i.enc_public));
}
