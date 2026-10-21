//! Тесты личности (crypto/identity.zig): детерминизм из сида, bundle и
//! отпечаток, подпись/проверка, обнуление deinit, pairSecret.
//! Корень — шаг test-crypto (zig build test-crypto).
const std = @import("std");
const stille_messenger = @import("stille-messenger");

const identity = stille_messenger.crypto.identity;
const Identity = identity.Identity;
const fingerprint_length = identity.fingerprint_length;

test "identity: детерминизм из сида" {
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @truncate(i *% 31 +% 5);

    const a = try Identity.fromSeed(seed);
    const b = try Identity.fromSeed(seed);
    try std.testing.expectEqualSlices(u8, &a.enc_secret, &b.enc_secret);
    try std.testing.expectEqualSlices(u8, &a.enc_public, &b.enc_public);
    try std.testing.expectEqualSlices(u8, &a.sign_public, &b.sign_public);
    try std.testing.expectEqualSlices(u8, &a.bundle(), &b.bundle());
}

test "identity: разные сиды -> разные ключи" {
    var seed_a: [32]u8 = @splat(1);
    var seed_b: [32]u8 = @splat(2);

    const a = try Identity.fromSeed(seed_a);
    const b = try Identity.fromSeed(seed_b);
    try std.testing.expect(!std.mem.eql(u8, &a.enc_public, &b.enc_public));
    try std.testing.expect(!std.mem.eql(u8, &a.sign_public, &b.sign_public));
    try std.testing.expect(!std.mem.eql(u8, &a.bundle(), &b.bundle()));
    try std.testing.expect(!std.mem.eql(u8, &a.enc_secret, &b.enc_secret));
    try std.testing.expect(!std.mem.eql(u8, &a.sign_kp.secret_key.bytes, &b.sign_kp.secret_key.bytes));

    // сид из всех нулей тоже валиден и детерминистичен
    seed_a = @splat(0);
    seed_b = @splat(0);
    const c = try Identity.fromSeed(seed_a);
    const d = try Identity.fromSeed(seed_b);
    try std.testing.expectEqualSlices(u8, &c.sign_public, &d.sign_public);
}

test "identity: bundle и формат отпечатка" {
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @truncate(i *% 17 +% 3);
    const id = try Identity.fromSeed(seed);

    const b = id.bundle();
    try std.testing.expectEqual(@as(usize, 64), b.len);
    try std.testing.expectEqualSlices(u8, &id.enc_public, b[0..32]);
    try std.testing.expectEqualSlices(u8, &id.sign_public, b[32..64]);

    var buf: [fingerprint_length]u8 = undefined;
    const fp = try id.fingerprintTo(&buf);
    try std.testing.expectEqual(@as(usize, fingerprint_length), fp.len);
    try std.testing.expectEqualSlices(u8, fp, &buf);

    // формат: 16 групп по 4 hex-символа через одиночные пробелы, lowercase
    for (fp, 0..) |ch, i| {
        if (i % 5 == 4) {
            try std.testing.expectEqual(@as(u8, ' '), ch);
        } else {
            const is_hex = (ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f');
            try std.testing.expect(is_hex);
        }
    }

    // детерминизм отпечатка и различие между сидами
    const id2 = try Identity.fromSeed(seed);
    var buf2: [fingerprint_length]u8 = undefined;
    try std.testing.expectEqualSlices(u8, fp, try id2.fingerprintTo(&buf2));

    const id3 = try Identity.fromSeed(@splat(9));
    var buf3: [fingerprint_length]u8 = undefined;
    try std.testing.expect(!std.mem.eql(u8, fp, try id3.fingerprintTo(&buf3)));

    // малый буфер
    var tiny: [fingerprint_length - 1]u8 = undefined;
    try std.testing.expectError(error.NoSpaceLeft, id.fingerprintTo(&tiny));
}

test "identity: подпись и проверка" {
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @truncate(i *% 13 +% 2);
    const id = try Identity.fromSeed(seed);

    const msg = "stille-messenger transcript";
    var sig: [64]u8 = undefined;
    try id.sign(msg, &sig);
    try Identity.verify(id.sign_public, msg, sig);

    // подменённое сообщение -> BadSignature
    try std.testing.expectError(error.BadSignature, Identity.verify(id.sign_public, "stille-messenger tampered", sig));

    // чужой публичный ключ -> BadSignature
    const other = try Identity.fromSeed(@splat(42));
    try std.testing.expectError(error.BadSignature, Identity.verify(other.sign_public, msg, sig));
}

test "identity: deinit обнуляет секреты" {
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @truncate(i +% 100);
    var id = try Identity.fromSeed(seed);

    const zeros: [32]u8 = @splat(0);
    var enc_copy: [32]u8 = id.enc_secret;
    var sign_copy: [64]u8 = id.sign_kp.secret_key.bytes;
    try std.testing.expect(!std.mem.eql(u8, &enc_copy, &zeros));

    id.deinit();
    try std.testing.expectEqualSlices(u8, &zeros, &id.enc_secret);
    const sk_zeros: [64]u8 = @splat(0);
    try std.testing.expectEqualSlices(u8, &sk_zeros, &id.sign_kp.secret_key.bytes);
    try std.testing.expect(!std.mem.eql(u8, &enc_copy, &id.enc_secret));
    try std.testing.expect(!std.mem.eql(u8, &sign_copy, &id.sign_kp.secret_key.bytes));
}

test "identity: pairSecret симметричен и зависит от пары" {
    const a = try Identity.fromSeed(@splat(@as(u8, 1)));
    const b = try Identity.fromSeed(@splat(@as(u8, 2)));
    const c = try Identity.fromSeed(@splat(@as(u8, 3)));
    const s_ab1 = try a.pairSecret(b.bundle());
    const s_ba = try b.pairSecret(a.bundle());
    try std.testing.expectEqualSlices(u8, &s_ab1, &s_ba); // статик-статик DH
    const s_ac = try a.pairSecret(c.bundle());
    try std.testing.expect(!std.mem.eql(u8, &s_ab1, &s_ac));
    // дегенерат: свой паблик (не должен совпадать с чужим секретом)
    const s_aa = try a.pairSecret(a.bundle());
    try std.testing.expect(!std.mem.eql(u8, &s_ab1, &s_aa));
}
