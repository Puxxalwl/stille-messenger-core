//! Тесты recovery-пакета (crypto/recovery.zig): roundtrip профиля,
//! чужой секрет/порча, лимиты полей, максимум, строгий разбор.
//! Корень — шаг test-crypto (zig build test-crypto).
const std = @import("std");
const stille_messenger = @import("stille-messenger");

const recovery = stille_messenger.crypto.recovery;
// Приватный алиас исходного файла (см. recovery.zig), воссоздан локально.
const aead = stille_messenger.crypto.aead;

const Plain = recovery.Plain;
const seal = recovery.seal;
const open = recovery.open;
const deriveKey = recovery.deriveKey;
const plaintextLen = recovery.plaintextLen;
const magic = recovery.magic;
const format_version = recovery.format_version;
const header_len = recovery.header_len;
const nonce_length = recovery.nonce_length;
const max_name = recovery.max_name;
const max_avatar = recovery.max_avatar;
const max_cfg = recovery.max_cfg;
const max_contacts = recovery.max_contacts;
const min_contact_rec = recovery.min_contact_rec;
const max_contact_rec = recovery.max_contact_rec;
const max_blocks = recovery.max_blocks;
const block_rec_len = recovery.block_rec_len;
const max_plaintext = recovery.max_plaintext;
const min_plaintext = recovery.min_plaintext;
const min_backup_len = recovery.min_backup_len;
const max_backup_len = recovery.max_backup_len;

const testing = std.testing;

// фикстуры уровня файла: срезы в Plain обязаны пережить вызов
const t_seed: [32]u8 = @splat(0x5A);
const t_name = "stille";
const t_avatar: [7]u8 = @splat(0x91);
const t_cfg = [_]u8{ 1, 0, 0, 0, 0 };
// контактная запись: nlen=3, «bob», bundle 64, хвост alen=0 (70 ≥ 66)
const t_contact: [70]u8 = blk: {
    var rec: [70]u8 = @splat(0);
    rec[0] = 3;
    rec[1] = 'b';
    rec[2] = 'o';
    rec[3] = 'b';
    break :blk rec;
};
const t_block: [65]u8 = blk: {
    var rec: [65]u8 = @splat(0);
    rec[64] = 1;
    break :blk rec;
};
// массивы срезов — тоже уровень файла: Plain заимствует их, локали
// examplePlain умерли бы вместе с возвратом
const t_contacts: [1][]const u8 = .{&t_contact};
const t_blocks: [1][]const u8 = .{&t_block};

fn examplePlain() Plain {
    return .{
        .seed = t_seed,
        .name = t_name,
        .avatar = &t_avatar,
        .cfg = &t_cfg,
        .contacts = t_contacts[0..],
        .blocks = t_blocks[0..],
    };
}

test "recovery: roundtrip полного профиля" {
    const alloc = testing.allocator;
    const secret: [32]u8 = @splat(0x11);
    const nonce: [nonce_length]u8 = @splat(0x22);

    const plain = examplePlain();
    const sealed = try seal(alloc, plain, &secret, nonce);
    defer alloc.free(sealed);
    try testing.expectEqual(header_len + plaintextLen(&plain) + aead.tag_length, sealed.len);
    try testing.expectEqual(magic, std.mem.readInt(u16, sealed[0..2], .little));
    try testing.expectEqual(format_version, sealed[2]);

    var backup = try open(alloc, sealed, &secret);
    defer backup.deinit(alloc);
    try testing.expectEqualSlices(u8, &plain.seed, &backup.seed);
    try testing.expectEqualSlices(u8, plain.name, backup.name);
    try testing.expectEqualSlices(u8, plain.avatar, backup.avatar);
    try testing.expectEqualSlices(u8, plain.cfg, backup.cfg);
    try testing.expectEqual(plain.contacts.len, backup.contacts.len);
    try testing.expectEqualSlices(u8, plain.contacts[0], backup.contacts[0]);
    try testing.expectEqual(plain.blocks.len, backup.blocks.len);
    try testing.expectEqualSlices(u8, plain.blocks[0], backup.blocks[0]);
    // блоб не должен содержать открытый текст подряд
    try testing.expect(!std.mem.eql(u8, sealed[header_len .. header_len + 16], backup.buf[0..16]));
}

test "recovery: пустой профиль roundtrip" {
    const alloc = testing.allocator;
    const secret: [32]u8 = @splat(1);
    const plain = Plain{ .seed = @splat(2) };
    const sealed = try seal(alloc, plain, &secret, @splat(0));
    defer alloc.free(sealed);
    try testing.expectEqual(min_backup_len, sealed.len);

    var backup = try open(alloc, sealed, &secret);
    defer backup.deinit(alloc);
    try testing.expectEqualSlices(u8, &plain.seed, &backup.seed);
    try testing.expectEqual(@as(usize, 0), backup.name.len);
    try testing.expectEqual(@as(usize, 0), backup.avatar.len);
    try testing.expectEqual(@as(usize, 0), backup.cfg.len);
    try testing.expectEqual(@as(usize, 0), backup.contacts.len);
    try testing.expectEqual(@as(usize, 0), backup.blocks.len);
}

test "recovery: чужой секрет и порча -> Tampered" {
    const alloc = testing.allocator;
    const secret: [32]u8 = @splat(0x33);
    const other: [32]u8 = @splat(0x44);
    const plain = examplePlain();
    const sealed = try seal(alloc, plain, &secret, @splat(0x55));
    defer alloc.free(sealed);

    // чужой секрет
    try testing.expectError(error.Tampered, open(alloc, sealed, &other));

    // порча шифротекста (не заголовка)
    var bad = try alloc.dupe(u8, sealed);
    defer alloc.free(bad);
    bad[header_len + 3] ^= 0x01;
    try testing.expectError(error.Tampered, open(alloc, bad, &secret));

    // порча тега
    bad[bad.len - 1] ^= 0x80;
    try testing.expectError(error.Tampered, open(alloc, bad, &secret));

    // порча nonce в заголовке: AD и расшифровка разъезжаются -> Tampered
    var bad2 = try alloc.dupe(u8, sealed);
    defer alloc.free(bad2);
    bad2[5] ^= 0x01;
    try testing.expectError(error.Tampered, open(alloc, bad2, &secret));
}

test "recovery: битый заголовок/длина -> BadFormat" {
    const alloc = testing.allocator;
    const secret: [32]u8 = @splat(0x66);
    const plain = examplePlain();
    const sealed = try seal(alloc, plain, &secret, @splat(0));
    defer alloc.free(sealed);

    // пусто и короче минимума; обрезка хвоста (байт тега) — это порча
    // box, а не структуры: детерминированный Tampered
    try testing.expectError(error.BadFormat, open(alloc, &.{}, &secret));
    try testing.expectError(error.BadFormat, open(alloc, sealed[0 .. min_backup_len - 1], &secret));
    try testing.expectError(error.Tampered, open(alloc, sealed[0 .. sealed.len - 1], &secret));

    // мусорная магия
    var bad = try alloc.dupe(u8, sealed);
    defer alloc.free(bad);
    bad[0] = 0x00;
    try testing.expectError(error.BadFormat, open(alloc, bad, &secret));

    // неизвестная версия формата (байт магии вернуть)
    bad[0] = sealed[0];
    bad[2] = 2;
    try testing.expectError(error.BadFormat, open(alloc, bad, &secret));
}

test "recovery: пределы полей на seal" {
    const alloc = testing.allocator;
    const secret: [32]u8 = @splat(7);
    const nonce: [nonce_length]u8 = @splat(0);

    // имя длиннее 32
    const long_name: [max_name + 1]u8 = @splat(0x61);
    try testing.expectError(error.TooBig, seal(alloc, .{ .seed = @splat(1), .name = &long_name }, &secret, nonce));

    // аватар больше 16000
    const long_avatar: [max_avatar + 1]u8 = @splat(0);
    try testing.expectError(error.TooBig, seal(alloc, .{ .seed = @splat(1), .avatar = &long_avatar }, &secret, nonce));

    // контактов больше 256: 257 записей минимальной длины
    const short_rec: [min_contact_rec]u8 = @splat(1);
    const short_slice: []const u8 = &short_rec;
    var many: [max_contacts + 1][]const u8 = @splat(short_slice);
    try testing.expectError(error.TooBig, seal(alloc, .{ .seed = @splat(1), .contacts = many[0..] }, &secret, nonce));

    // блокировок больше 256
    const block_slice: []const u8 = &t_block;
    var many_blocks: [max_blocks + 1][]const u8 = @splat(block_slice);
    try testing.expectError(error.TooBig, seal(alloc, .{ .seed = @splat(1), .blocks = many_blocks[0..] }, &secret, nonce));

    // контактная запись вне 66..232
    const tiny_rec: [65]u8 = @splat(0);
    var tiny: [1][]const u8 = .{&tiny_rec};
    try testing.expectError(error.BadFormat, seal(alloc, .{ .seed = @splat(1), .contacts = tiny[0..] }, &secret, nonce));
    const huge_rec: [max_contact_rec + 1]u8 = @splat(0);
    var huge: [1][]const u8 = .{&huge_rec};
    try testing.expectError(error.BadFormat, seal(alloc, .{ .seed = @splat(1), .contacts = huge[0..] }, &secret, nonce));

    // блокировка не 65 байт / flag вне 0..1
    const bad_block: [65]u8 = blk: {
        var rec: [65]u8 = @splat(0);
        rec[64] = 2;
        break :blk rec;
    };
    var one_bad: [1][]const u8 = .{&bad_block};
    try testing.expectError(error.BadFormat, seal(alloc, .{ .seed = @splat(1), .blocks = one_bad[0..] }, &secret, nonce));
    const short_block: [64]u8 = @splat(0);
    var one_short: [1][]const u8 = .{&short_block};
    try testing.expectError(error.BadFormat, seal(alloc, .{ .seed = @splat(1), .blocks = one_short[0..] }, &secret, nonce));
}

test "recovery: максимум профиля проходит и лимит блоба держится" {
    const alloc = testing.allocator;
    const secret: [32]u8 = @splat(0x77);
    const nonce: [nonce_length]u8 = @splat(0x99);

    // запись на максимум: nlen 32 + bundle + оба адресных хвоста
    const full_rec: [max_contact_rec]u8 = blk: {
        var rec: [max_contact_rec]u8 = @splat(0);
        rec[0] = 32;
        var n: usize = 1;
        @memset(rec[n .. n + 32], 0x61);
        n += 32 + 64;
        // [alen][host 64][port]
        rec[n] = 64;
        n += 1;
        @memset(rec[n .. n + 64], 0x62);
        n += 64;
        std.mem.writeInt(u16, rec[n..][0..2], 7777, .little);
        n += 2;
        // [rlen][rhost 64][port]
        rec[n] = 64;
        n += 1;
        @memset(rec[n .. n + 64], 0x63);
        n += 64;
        std.mem.writeInt(u16, rec[n..][0..2], 9000, .little);
        break :blk rec;
    };
    var recs: [max_contacts][]const u8 = @splat(&full_rec);
    var blks: [max_blocks][]const u8 = @splat(&t_block);
    const long_avatar: [max_avatar]u8 = @splat(0x91);
    const long_name: [max_name]u8 = @splat(0x6E);
    const long_cfg: [max_cfg]u8 = @splat(1);
    const plain = Plain{
        .seed = @splat(0x88),
        .name = &long_name,
        .avatar = &long_avatar,
        .cfg = &long_cfg,
        .contacts = recs[0..],
        .blocks = blks[0..],
    };
    try testing.expectEqual(max_plaintext, plaintextLen(&plain));

    const sealed = try seal(alloc, plain, &secret, nonce);
    defer alloc.free(sealed);
    try testing.expectEqual(max_backup_len, sealed.len);

    var backup = try open(alloc, sealed, &secret);
    defer backup.deinit(alloc);
    try testing.expectEqual(max_contacts, backup.contacts.len);
    try testing.expectEqual(max_blocks, backup.blocks.len);
    try testing.expectEqualSlices(u8, &plain.seed, &backup.seed);
    try testing.expectEqualSlices(u8, &long_avatar, backup.avatar);
    try testing.expectEqualSlices(u8, &full_rec, backup.contacts[0]);
    try testing.expectEqualSlices(u8, &long_name, backup.name);
    try testing.expectEqualSlices(u8, &long_cfg, backup.cfg);
}

test "recovery: разбор отвергает счётчики-ложь, версию и хвост" {
    const alloc = testing.allocator;
    const secret: [32]u8 = @splat(0xAA);
    const nonce: [nonce_length]u8 = @splat(0xBB);

    // открытый текст 40 байт: ver, seed, пустые имя/аватар/cfg,
    // contacts = 1, но записи нет
    var pt: [min_plaintext]u8 = @splat(0);
    pt[0] = format_version;
    @memcpy(pt[1..33], &t_seed);
    std.mem.writeInt(u16, pt[38..40], 1, .little);

    var key = deriveKey(&secret);
    defer std.crypto.secureZero(u8, &key);
    var sealed: [header_len + min_plaintext + aead.tag_length]u8 = undefined;
    std.mem.writeInt(u16, sealed[0..2], magic, .little);
    sealed[2] = format_version;
    @memcpy(sealed[3..header_len], &nonce);
    aead.seal(sealed[header_len..], &pt, key, nonce, sealed[0..header_len]);
    try testing.expectError(error.BadFormat, open(alloc, &sealed, &secret));

    // версия внутри открытого текста не 1
    pt[0] = 2;
    aead.seal(sealed[header_len..], &pt, key, nonce, sealed[0..header_len]);
    try testing.expectError(error.BadFormat, open(alloc, &sealed, &secret));
    pt[0] = format_version;
    std.mem.writeInt(u16, pt[38..40], 0, .little);
    aead.seal(sealed[header_len..], &pt, key, nonce, sealed[0..header_len]);
    var ok_backup = try open(alloc, &sealed, &secret);
    defer ok_backup.deinit(alloc);
    try testing.expectEqualSlices(u8, &t_seed, &ok_backup.seed);

    // лишний хвост в открытом тексте: 41-й байт
    var pt2: [min_plaintext + 1]u8 = @splat(0);
    @memcpy(pt2[0..min_plaintext], &pt);
    var sealed2: [header_len + pt2.len + aead.tag_length]u8 = undefined;
    std.mem.writeInt(u16, sealed2[0..2], magic, .little);
    sealed2[2] = format_version;
    @memcpy(sealed2[3..header_len], &nonce);
    aead.seal(sealed2[header_len..], &pt2, key, nonce, sealed2[0..header_len]);
    try testing.expectError(error.BadFormat, open(alloc, &sealed2, &secret));
}

test "recovery: ключ детерминирован и зависит от секрета" {
    const a: [32]u8 = @splat(1);
    const b: [32]u8 = @splat(2);
    const k1 = deriveKey(&a);
    const k2 = deriveKey(&a);
    const k3 = deriveKey(&b);
    try testing.expectEqualSlices(u8, &k1, &k2);
    try testing.expect(!std.mem.eql(u8, &k1, &k3));
}

test "recovery: разные nonce дают разные блобы, оба открываются" {
    const alloc = testing.allocator;
    const secret: [32]u8 = @splat(3);
    const plain = examplePlain();
    const s1 = try seal(alloc, plain, &secret, @splat(0));
    defer alloc.free(s1);
    const s2 = try seal(alloc, plain, &secret, @splat(1));
    defer alloc.free(s2);
    try testing.expect(!std.mem.eql(u8, s1, s2));
    var b1 = try open(alloc, s1, &secret);
    defer b1.deinit(alloc);
    var b2 = try open(alloc, s2, &secret);
    defer b2.deinit(alloc);
    try testing.expectEqualSlices(u8, &b1.seed, &b2.seed);
}
