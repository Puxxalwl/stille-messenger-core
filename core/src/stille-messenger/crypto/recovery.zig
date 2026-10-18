//! Recovery-пакет аккаунта: запечатанный AEAD-блоб для восстановления
//! доступа к личности БЕЗ истории (сборку из живого профиля и применение
//! к пустому делает app/recovery.zig; сценарий — CORE-API.md §4.10).
//!
//! Модель: GUI получает от пользователя 32-байтный секрет разблокировки
//! (passkey PRF-расширение или recovery-код) и передаёт его ядру по UDS;
//! ядро запечатывает сид+профиль+контакты и отдаёт блоб. GUI хранит блоб в
//! пользовательском облаке (Google Drive и т.п.) — облако и GUI без секрета
//! видят только шифротекст. Ключ выводится HKDF от секрета и живёт в ядре
//! ровно на время seal/open (обнуляется после).
//!
//! Формат (little-endian, никаких JSON/varint):
//!
//!     sealed = header || box
//!     header = [magic u16 = 0x5A52][ver u8 = 1][nonce 12]
//!     box    = ChaCha20-Poly1305(plain, key, nonce, ad = header)
//!              = ciphertext || tag[16]
//!     plain  = [ver u8 = 1][seed 32]
//!              [name_len u8 ≤ 32][name]
//!              [avatar_len u16 ≤ 16000][avatar]
//!              [cfg_len u16 ≤ 137][cfg blob (app/config.zig)]
//!              [n_contacts u16 ≤ 256] × {[rec_len u16 66..232][contact_rec]}
//!              [n_blocks u16 ≤ 256] × {[bundle 64][flag u8 0/1]}
//!
//! Контактная запись и блокировка — байты формата зашифрованного лога
//! (kind contact / kind block) как есть: восстановление дописывает их в
//! новый лог без перекодирования, загрузчик контактов не меняется.
//!
//! Ключ: key = HKDF-SHA256(ikm = unlock_secret,
//! salt = "shopot-recovery-v1", info = "recovery-backup-v1"). Nonce —
//! случайные 96 бит на каждый backup (задаёт вызывающий, вне модуля):
//! один backup = одно AEAD-сообщение, вероятность повтора (key, nonce)
//! значима лишь после ~2^48 пакетов одного пользователя (парадокс дней
//! рождения на 96-битном пространстве) — за пределами любого профиля.
//!
//! Разбор строго однозначен: точное потребление plain, все счётчики и
//! длины проверяются против лимитов, лишний байт = BadFormat. Пределы
//! размера — явные константы ниже (ограниченный ресурс: блоб уходит в
//! облако и в кадр UDS, память под него конечна).

const std = @import("std");
const aead = @import("aead.zig");

/// HKDF-SHA256 для вывода ключа пакета.
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
/// Соль домена вывода (отлична от «shopot-store-v3» и «shopot-device-sync-v1»).
const kdf_salt = "shopot-recovery-v1";
/// Info-домен вывода ключа пакета.
const kdf_info = "recovery-backup-v1";

/// Магия пакета: 0x5A52.
pub const magic: u16 = 0x5A52;
/// Версия формата пакета.
pub const format_version: u8 = 1;

/// Длина открытого заголовка: magic + ver + nonce.
pub const header_len: usize = 2 + 1 + aead.nonce_length;
/// Длина секрета разблокировки (PRF-выход GUI / recovery-код).
pub const secret_length: usize = 32;
/// Длина nonce (совпадает с nonce AEAD).
pub const nonce_length = aead.nonce_length;

/// Максимум имени профиля (как invite_mod.max_name).
pub const max_name: usize = 32;
/// Максимум байтов аватара (как envelope.max_avatar_data).
pub const max_avatar: usize = 16000;
/// Максимум cfg-blob (app/config.zig: ver+flags+два str16 по 64).
pub const max_cfg: usize = 1 + 4 + 2 + 64 + 2 + 64;
/// Максимум контактов в пакете.
pub const max_contacts: usize = 256;
/// Минимум контактной записи (nlen ≥ 1 + bundle 64 + хвост alen ≥ 1).
pub const min_contact_rec: usize = 66;
/// Максимум контактной записи (nlen 32 + bundle + оба хвоста адресов
/// + хвостовой байт роли устройства).
pub const max_contact_rec: usize = 1 + 32 + 64 + 1 + 64 + 2 + 1 + 64 + 2 + 1;
/// Максимум блокировок в пакете.
pub const max_blocks: usize = 256;
/// Длина записи блокировки ([bundle 64][flag u8]).
pub const block_rec_len: usize = 65;

/// Максимум открытого текста пакета (все поля на максимумах).
pub const max_plaintext: usize = blk: {
    const fixed = 1 + 32 + 1 + max_name + 2 + max_avatar + 2 + max_cfg + 2 + 2;
    const contacts = max_contacts * (2 + max_contact_rec);
    const blocks = max_blocks * block_rec_len;
    break :blk fixed + contacts + blocks;
};
/// Минимум открытого текста (все поля пустые).
pub const min_plaintext: usize = 1 + 32 + 1 + 2 + 2 + 2 + 2;
/// Минимум запечатанного пакета: header + min plain + tag.
pub const min_backup_len: usize = header_len + min_plaintext + aead.tag_length;
/// Максимум запечатанного пакета: header + max plain + tag.
pub const max_backup_len: usize = header_len + max_plaintext + aead.tag_length;

comptime {
    std.debug.assert(max_contact_rec == 232);
    std.debug.assert(min_plaintext == 42);
    std.debug.assert(max_backup_len < 100 * 1024);
}

/// Ошибки модуля: формат/лимиты — на запечатывании и разборе,
/// Tampered — тег не сошёлся (чужой секрет, порча блоба/заголовка).
pub const Error = error{
    BadFormat,
    TooBig,
    Tampered,
    OutOfMemory,
};

/// Открытый профиль пакета: заимствованные срезы (живут до seal).
pub const Plain = struct {
    /// Сид личности (32 байта; копируется внутрь пакета).
    seed: [32]u8,
    /// Имя профиля (0..max_name; пустое — профиль без имени).
    name: []const u8 = "",
    /// Байты аватара (0..max_avatar; пусто — аватара нет).
    avatar: []const u8 = "",
    /// cfg-blob формата app/config.zig (0..max_cfg; пусто — дефолты).
    cfg: []const u8 = "",
    /// Контактные записи формата лога (kind contact), 66..232 байта.
    contacts: []const []const u8 = &.{},
    /// Записи блокировок формата лога (kind block), ровно 65 байт.
    blocks: []const []const u8 = &.{},
};

/// Распакованный пакет: владеет буфером открытого текста (в нём сид —
/// deinit обнуляет буфер перед освобождением) и массивами срезов.
pub const Backup = struct {
    /// Открытый текст пакета (owned; содержит сид — обнуляется в deinit).
    buf: []u8,
    /// Контакты: срезы (owned-массив) записей формата лога, каждый в buf.
    contacts: []const []const u8 = &.{},
    /// Блокировки: срезы (owned-массив) по 65 байт из buf.
    blocks: []const []const u8 = &.{},
    /// Сид личности.
    seed: [32]u8,
    /// Имя профиля (заимствует buf).
    name: []u8,
    /// Байты аватара (заимствует buf).
    avatar: []u8,
    /// cfg-blob (заимствует buf; пусто — дефолты).
    cfg: []u8,

    /// Освободить буферы; сид в buf обнуляется до освобождения.
    pub fn deinit(self: *Backup, alloc: std.mem.Allocator) void {
        alloc.free(self.contacts);
        alloc.free(self.blocks);
        std.crypto.secureZero(u8, self.buf);
        alloc.free(self.buf);
        std.crypto.secureZero(u8, &self.seed);
    }
};

/// Ключ пакета из секрета разблокировки (отдельный домен HKDF).
pub fn deriveKey(unlock_secret: *const [secret_length]u8) [32]u8 {
    var prk: [HkdfSha256.prk_length]u8 = HkdfSha256.extract(kdf_salt, unlock_secret);
    defer std.crypto.secureZero(u8, &prk);
    var key: [32]u8 = undefined;
    HkdfSha256.expand(&key, kdf_info, prk);
    return key;
}

/// Точный размер открытого текста профиля.
pub fn plaintextLen(plain: *const Plain) usize {
    var n: usize = 1 + 32 + 1 + plain.name.len + 2 + plain.avatar.len + 2 + plain.cfg.len + 2;
    for (plain.contacts) |rec| n += 2 + rec.len;
    n += 2;
    n += plain.blocks.len * block_rec_len;
    return n;
}

/// Проверить пределы полей (без аллокаций; вызывается seal и тестами).
pub fn validatePlain(plain: *const Plain) Error!void {
    if (plain.name.len > max_name) return error.TooBig;
    if (plain.avatar.len > max_avatar) return error.TooBig;
    if (plain.cfg.len > max_cfg) return error.TooBig;
    if (plain.contacts.len > max_contacts) return error.TooBig;
    for (plain.contacts) |rec| {
        if (rec.len < min_contact_rec or rec.len > max_contact_rec) return error.BadFormat;
    }
    if (plain.blocks.len > max_blocks) return error.TooBig;
    for (plain.blocks) |rec| {
        if (rec.len != block_rec_len) return error.BadFormat;
        if (rec[64] > 1) return error.BadFormat;
    }
    if (plaintextLen(plain) > max_plaintext) return error.TooBig;
}

/// Запечатать профиль: sealed = header || box. `nonce` задаёт вызывающий
/// (io.random вне блокировок приложения). Возвращает owned-блоб.
pub fn seal(alloc: std.mem.Allocator, plain: Plain, unlock_secret: *const [secret_length]u8, nonce: [nonce_length]u8) Error![]u8 {
    try validatePlain(&plain);
    const pt_len = plaintextLen(&plain);

    const sealed = alloc.alloc(u8, header_len + pt_len + aead.tag_length) catch return error.OutOfMemory;
    errdefer alloc.free(sealed);

    // открытый текст во временном буфере: после seal обнуляется (там сид)
    const pt = alloc.alloc(u8, pt_len) catch return error.OutOfMemory;
    defer {
        std.crypto.secureZero(u8, pt);
        alloc.free(pt);
    }
    encodePlaintext(pt, plain);

    std.mem.writeInt(u16, sealed[0..2], magic, .little);
    sealed[2] = format_version;
    @memcpy(sealed[3..header_len], &nonce);

    var key = deriveKey(unlock_secret);
    defer std.crypto.secureZero(u8, &key);
    aead.seal(sealed[header_len..], pt, key, nonce, sealed[0..header_len]);
    return sealed;
}

/// Распечатать и разобрать пакет. Ошибки: BadFormat — структура/заголовок,
/// Tampered — тег (чужой секрет или порча). Владение буферами переходит
/// в Backup (deinit освобождает).
pub fn open(alloc: std.mem.Allocator, sealed: []const u8, unlock_secret: *const [secret_length]u8) Error!Backup {
    if (sealed.len < min_backup_len) return error.BadFormat;
    if (sealed.len > max_backup_len) return error.TooBig;
    if (std.mem.readInt(u16, sealed[0..2], .little) != magic) return error.BadFormat;
    if (sealed[2] != format_version) return error.BadFormat;

    const nonce: [nonce_length]u8 = sealed[3..header_len].*;
    const box_ = sealed[header_len..];
    const pt_len = box_.len - aead.tag_length;

    const pt = alloc.alloc(u8, pt_len) catch return error.OutOfMemory;
    errdefer {
        std.crypto.secureZero(u8, pt);
        alloc.free(pt);
    }
    var key = deriveKey(unlock_secret);
    defer std.crypto.secureZero(u8, &key);
    aead.open(pt, box_, key, nonce, sealed[0..header_len]) catch |e| switch (e) {
        error.Tampered => return error.Tampered,
        error.TooShort => return error.BadFormat,
    };
    return parsePlaintext(alloc, pt);
}

/// Собрать открытый текст в `pt` (валидирован validatePlain).
fn encodePlaintext(pt: []u8, plain: Plain) void {
    var n: usize = 0;
    pt[n] = format_version;
    n += 1;
    @memcpy(pt[n..][0..32], &plain.seed);
    n += 32;
    pt[n] = @intCast(plain.name.len);
    n += 1;
    @memcpy(pt[n..][0..plain.name.len], plain.name);
    n += plain.name.len;
    std.mem.writeInt(u16, pt[n..][0..2], @intCast(plain.avatar.len), .little);
    n += 2;
    @memcpy(pt[n..][0..plain.avatar.len], plain.avatar);
    n += plain.avatar.len;
    std.mem.writeInt(u16, pt[n..][0..2], @intCast(plain.cfg.len), .little);
    n += 2;
    @memcpy(pt[n..][0..plain.cfg.len], plain.cfg);
    n += plain.cfg.len;
    std.mem.writeInt(u16, pt[n..][0..2], @intCast(plain.contacts.len), .little);
    n += 2;
    for (plain.contacts) |rec| {
        std.mem.writeInt(u16, pt[n..][0..2], @intCast(rec.len), .little);
        n += 2;
        @memcpy(pt[n..][0..rec.len], rec);
        n += rec.len;
    }
    std.mem.writeInt(u16, pt[n..][0..2], @intCast(plain.blocks.len), .little);
    n += 2;
    for (plain.blocks) |rec| {
        @memcpy(pt[n..][0..block_rec_len], rec);
        n += block_rec_len;
    }
    std.debug.assert(n == pt.len);
}

/// Разобрать открытый текст (после AEAD-open). Строгая, без двусмысленностей:
/// точное потребление, все счётчики против лимитов, версии поля тоже.
fn parsePlaintext(alloc: std.mem.Allocator, pt: []u8) Error!Backup {
    var contacts: ?[]([]const u8) = null;
    var blocks: ?[]([]const u8) = null;
    errdefer {
        if (contacts) |c| alloc.free(c);
        if (blocks) |b| alloc.free(b);
    }

    var pos: usize = 0;
    // ver
    if (pos + 1 > pt.len) return error.BadFormat;
    if (pt[pos] != format_version) return error.BadFormat;
    pos += 1;
    // seed
    if (pos + 32 > pt.len) return error.BadFormat;
    const seed: [32]u8 = pt[pos..][0..32].*;
    pos += 32;
    // name
    if (pos + 1 > pt.len) return error.BadFormat;
    const name_len: usize = pt[pos];
    if (name_len > max_name) return error.BadFormat;
    pos += 1;
    if (pos + name_len > pt.len) return error.BadFormat;
    const name = pt[pos..][0..name_len];
    pos += name_len;
    // avatar
    if (pos + 2 > pt.len) return error.BadFormat;
    const avatar_len: usize = std.mem.readInt(u16, pt[pos..][0..2], .little);
    if (avatar_len > max_avatar) return error.BadFormat;
    pos += 2;
    if (pos + avatar_len > pt.len) return error.BadFormat;
    const avatar = pt[pos..][0..avatar_len];
    pos += avatar_len;
    // cfg
    if (pos + 2 > pt.len) return error.BadFormat;
    const cfg_len: usize = std.mem.readInt(u16, pt[pos..][0..2], .little);
    if (cfg_len > max_cfg) return error.BadFormat;
    pos += 2;
    if (pos + cfg_len > pt.len) return error.BadFormat;
    const cfg = pt[pos..][0..cfg_len];
    pos += cfg_len;
    // contacts
    if (pos + 2 > pt.len) return error.BadFormat;
    const n_contacts: usize = std.mem.readInt(u16, pt[pos..][0..2], .little);
    if (n_contacts > max_contacts) return error.BadFormat;
    pos += 2;
    if (n_contacts > 0) {
        const cs = alloc.alloc([]const u8, n_contacts) catch return error.OutOfMemory;
        contacts = cs;
        for (cs) |*slot| {
            if (pos + 2 > pt.len) return error.BadFormat;
            const rec_len: usize = std.mem.readInt(u16, pt[pos..][0..2], .little);
            if (rec_len < min_contact_rec or rec_len > max_contact_rec) return error.BadFormat;
            pos += 2;
            if (pos + rec_len > pt.len) return error.BadFormat;
            slot.* = pt[pos..][0..rec_len];
            pos += rec_len;
        }
    }
    // blocks
    if (pos + 2 > pt.len) return error.BadFormat;
    const n_blocks: usize = std.mem.readInt(u16, pt[pos..][0..2], .little);
    if (n_blocks > max_blocks) return error.BadFormat;
    pos += 2;
    if (n_blocks > 0) {
        const bs = alloc.alloc([]const u8, n_blocks) catch return error.OutOfMemory;
        blocks = bs;
        for (bs) |*slot| {
            if (pos + block_rec_len > pt.len) return error.BadFormat;
            if (pt[pos + 64] > 1) return error.BadFormat;
            slot.* = pt[pos..][0..block_rec_len];
            pos += block_rec_len;
        }
    }
    // точное потребление: лишний байт = двусмысленность = отказ
    if (pos != pt.len) return error.BadFormat;

    return .{
        .buf = pt,
        .contacts = contacts orelse &.{},
        .blocks = blocks orelse &.{},
        .seed = seed,
        .name = name,
        .avatar = avatar,
        .cfg = cfg,
    };
}

// ------------------------------------------------------------------ tests

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
