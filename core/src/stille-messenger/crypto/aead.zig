//! ChaCha20-Poly1305 AEAD (std.crypto.aead.chacha_poly.ChaCha20Poly1305).
//! Формат box: ciphertext || tag. Nonce собирается из u64-счётчика:
//! [0,0,0,0] || counter LE.

const std = @import("std");

const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

/// Длина тега Poly1305, в байтах.
pub const tag_length = Aead.tag_length;

/// Длина ключа, в байтах.
pub const key_length = Aead.key_length;

/// Длина nonce, в байтах.
pub const nonce_length = Aead.nonce_length;

/// Ошибки расшифровки: TooShort — мало данных или мал буфер вывода,
/// Tampered — тег не сошёлся (битые данные, чужой ключ/nonce/ad).
pub const Error = error{ Tampered, TooShort };

/// Собирает 12-байтовый nonce из 64-битного счётчика: [0,0,0,0] || counter LE.
pub fn nonceFor(counter: u64) [nonce_length]u8 {
    var nonce: [nonce_length]u8 = @splat(0);
    std.mem.writeInt(u64, nonce[4..12], counter, .little);
    return nonce;
}

/// Шифрует `plain` в `out_box` (длина >= plain.len + tag_length): ciphertext || tag.
pub fn seal(out_box: []u8, plain: []const u8, key: [key_length]u8, nonce: [nonce_length]u8, ad: []const u8) void {
    std.debug.assert(out_box.len >= plain.len + tag_length);
    const c = out_box[0..plain.len];
    const tag = out_box[plain.len..][0..tag_length];
    Aead.encrypt(c, tag, plain, ad, nonce, key);
}

/// Расшифровывает `box` (ciphertext || tag) в `plain_out` (длина >= box.len - tag_length).
pub fn open(plain_out: []u8, box: []const u8, key: [key_length]u8, nonce: [nonce_length]u8, ad: []const u8) Error!void {
    if (box.len < tag_length) return error.TooShort;
    const c_len = box.len - tag_length;
    if (plain_out.len < c_len) return error.TooShort;
    const tag: [tag_length]u8 = box[c_len..][0..tag_length].*;
    Aead.decrypt(plain_out[0..c_len], box[0..c_len], tag, ad, nonce, key) catch return error.Tampered;
}
