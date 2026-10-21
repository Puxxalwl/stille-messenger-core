//! HKDF-SHA256 (RFC 5869) — тонкие обёртки над std.crypto.kdf.
//! Собственных примитивов нет: только композиция std.

const std = @import("std");

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

/// Длина псевдослучайного ключа (PRK), в байтах (SHA-256 -> 32).
pub const prk_length = HkdfSha256.prk_length;

/// Фаза extract: prk = HMAC-SHA256(salt, ikm).
pub fn extract(salt: []const u8, ikm: []const u8) [prk_length]u8 {
    return HkdfSha256.extract(salt, ikm);
}

/// Фаза expand: заполняет `okm` выходным материалом HKDF-Expand(prk, info).
pub fn expand(prk: [prk_length]u8, info: []const u8, okm: []u8) void {
    HkdfSha256.expand(okm, info, prk);
}
