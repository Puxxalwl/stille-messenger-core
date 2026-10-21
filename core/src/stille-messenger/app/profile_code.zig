//! Профиль-код: вывод секрета инвайта профиля (HKDF от enc_secret
//! и эпохи) и идентификатора кода (BLAKE2s от bundle). Домен отделён
//! от инвайтов и релея.
const std = @import("std");
const stille_messenger = @import("stille-messenger");
const identity = stille_messenger.crypto.identity;

/// Статический секрет персистентного кода профиля (InviteExMode.profile):
/// HKDF-SHA256 из приватного enc-секрета личности (того же, что держит
/// relay-маркеры), с эпохой в info. Не хранится нигде: выводится на лету
/// при создании кода и при проверке JOIN. Свойства: знающий код может
/// добавить нас (как t.me-ссылку; от злоупотреблений BLOCK_CONTACT и
/// REGENERATE_PROFILE_CODE); подделать ДРУГОЙ валидный код нельзя —
/// секрет не выводится из публичного bundle; смена эпохи меняет секрет —
/// слитый код прошлой эпохи перестаёт проходить проверку JOIN.
pub const profile_secret_domain = "shopot-profile-code-v1";

pub fn profileSecret(id: *const identity.Identity, epoch: u32) [16]u8 {
    var info: [profile_secret_domain.len + 4]u8 = undefined;
    @memcpy(info[0..profile_secret_domain.len], profile_secret_domain);
    std.mem.writeInt(u32, info[profile_secret_domain.len..][0..4], epoch, .little);
    var okm: [16]u8 = undefined;
    std.crypto.kdf.hkdf.HkdfSha256.expand(&okm, &info, id.enc_secret);
    return okm;
}

/// invite_id персистентного кода профиля: детерминированный НЕсекретный
/// маркер (BLAKE2s-256(bundle)[0..16] — совпадает с отпечатком из
/// GET_IDENTITY). GET_INVITE_STATE по нему отвечает active/бессрочно.
pub fn profileInviteId(id: *const identity.Identity) [16]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(&(id.bundle()), &digest, .{});
    return digest[0..16].*;
}
