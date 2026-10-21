//! Одноразовые ключи аудиовызова: keyFor(seq) = HKDF-Expand(call_secret,
//! "shopot-call-v3" || u32 LE seq). Уникальность seq (одноразовость ключа) —
//! обязанность вызывающего.

const std = @import("std");

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

const domain = "shopot-call-v3";

/// Выводит 32-байтовый ключ аудиокадра для порядкового номера `seq`.
pub fn keyFor(call_secret: [32]u8, seq: u32) [32]u8 {
    var info: [domain.len + 4]u8 = undefined;
    @memcpy(info[0..domain.len], domain);
    std.mem.writeInt(u32, info[domain.len..][0..4], seq, .little);

    var key: [32]u8 = undefined;
    HkdfSha256.expand(&key, &info, call_secret);
    return key;
}
