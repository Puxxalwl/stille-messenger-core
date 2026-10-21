//! Личность из 32-байтного сида: ключ X25519 для шифрования и Ed25519 для
//! подписей. Скаляры выводятся HKDF-SHA256(seed, "shopot-id-v3"): 64 байта,
//! первые 32 — enc-сид X25519, следующие 32 — сид Ed25519. Пара Ed25519
//! выводится ОДИН раз при fromSeed и кэшируется: подпись не тянет за собой
//! повторный скалярный вывод (было: generateDeterministic на каждый sign).

const std = @import("std");

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const X25519 = std.crypto.dh.X25519;
const Ed25519 = std.crypto.sign.Ed25519;
const Blake2s256 = std.crypto.hash.blake2.Blake2s256;

const domain = "shopot-id-v3";

/// Длина bundle: enc_pk || sign_pk.
pub const bundle_length = 64;

/// Длина отпечатка в символах: 16 групп по 4 hex-символа + 15 пробелов.
pub const fingerprint_length = 79;

/// Ошибки выведения личности: вырожденный сид Ed25519 (практически
/// невозможен для качественного сида).
pub const Error = error{IdentityElement};

pub const Identity = struct {
    /// Приватный скаляр X25519 (обнуляется в deinit).
    enc_secret: [32]u8,
    /// Публичный ключ X25519.
    enc_public: [32]u8,
    /// Кэшированная пара Ed25519: sign() без повторного вывода пары.
    /// Секретные байты обнуляются в deinit.
    sign_kp: Ed25519.KeyPair,
    /// Публичный ключ Ed25519.
    sign_public: [32]u8,

    /// Выводит личность детерминистически из 32-байтного сида.
    pub fn fromSeed(seed: [32]u8) Error!Identity {
        var okm: [64]u8 = undefined;
        HkdfSha256.expand(&okm, domain, seed);

        const enc_kp = X25519.KeyPair.generateDeterministic(okm[0..32].*);
        const sign_kp = try Ed25519.KeyPair.generateDeterministic(okm[32..64].*);

        const id = Identity{
            .enc_secret = enc_kp.secret_key,
            .enc_public = enc_kp.public_key,
            .sign_kp = sign_kp,
            .sign_public = sign_kp.public_key.toBytes(),
        };
        @memset(&okm, 0);
        return id;
    }

    /// Парный ДОЛГОСРОЧНЫЙ секрет с контактом: X25519(мой статический
    /// enc-секрет, enc-паблик пира) — эквивалент pre-message ss из Noise KK:
    /// обе стороны выводят одно и то же значение, релей/наблюдатель его не
    /// знает. Основа релей-присутствия: marker спаривания без нового инвайта
    /// (relay.presenceMarker). Компромисция статического ключа раскрывает
    /// marker — но компромисция identity и так game-over.
    pub fn pairSecret(self: *const Identity, peer_bundle: [bundle_length]u8) error{InvalidPublicKey}![32]u8 {
        var peer_enc: [32]u8 = undefined;
        @memcpy(&peer_enc, peer_bundle[0..32]);
        return X25519.scalarmult(self.enc_secret, peer_enc) catch return error.InvalidPublicKey;
    }

    /// Bundle публичных ключей: enc_pk || sign_pk (64 байта).
    pub fn bundle(self: *const Identity) [bundle_length]u8 {
        var out: [bundle_length]u8 = undefined;
        out[0..32].* = self.enc_public;
        out[32..64].* = self.sign_public;
        return out;
    }

    /// Отпечаток: BLAKE2s-256(bundle), hex lowercase группами по 4 через пробел.
    /// Строка (без NUL) пишется в `buf`; требуется buf.len >= fingerprint_length.
    pub fn fingerprintTo(self: *const Identity, buf: []u8) error{NoSpaceLeft}![]const u8 {
        if (buf.len < fingerprint_length) return error.NoSpaceLeft;

        var digest: [32]u8 = undefined;
        const b = self.bundle();
        Blake2s256.hash(&b, &digest, .{});

        const hex = "0123456789abcdef";
        var pos: usize = 0;
        for (0..16) |group| {
            if (group != 0) {
                buf[pos] = ' ';
                pos += 1;
            }
            for (0..4) |nib| {
                const idx = group * 4 + nib;
                const byte = digest[idx / 2];
                const lo = idx % 2 == 1;
                buf[pos] = hex[if (lo) byte & 0x0f else byte >> 4];
                pos += 1;
            }
        }
        return buf[0..fingerprint_length];
    }

    /// Подписывает `msg` парой Ed25519 личности (пара уже выведена в
    /// fromSeed — повторного скалярного вывода нет); 64-байтовая подпись
    /// в `sig_out`. KeyMismatch недостижим: pk хранится вместе с секретом.
    pub fn sign(self: *const Identity, msg: []const u8, sig_out: *[64]u8) error{ IdentityElement, NonCanonical, KeyMismatch, WeakPublicKey }!void {
        const sig = try self.sign_kp.sign(msg, null);
        sig_out.* = sig.toBytes();
    }

    /// Проверяет подпись `sig` сообщения `msg` по публичному ключу Ed25519.
    pub fn verify(sign_public: [32]u8, msg: []const u8, sig: [64]u8) error{BadSignature}!void {
        const parsed = Ed25519.Signature.fromBytes(sig);
        const pk = Ed25519.PublicKey.fromBytes(sign_public) catch return error.BadSignature;
        parsed.verify(msg, pk) catch return error.BadSignature;
    }

    /// Обнуляет секретные скаляры личности.
    pub fn deinit(self: *Identity) void {
        std.crypto.secureZero(u8, &self.enc_secret);
        std.crypto.secureZero(u8, &self.sign_kp.secret_key.bytes);
    }
};
