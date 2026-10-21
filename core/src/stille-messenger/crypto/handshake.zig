//! XX-подобное гибридное рукопожатие: транскрипт BLAKE2s-256, DH X25519
//! (ee/es/se) и ephemeral ML-KEM-768 для защиты от store-now-decrypt-later.
//! Статики и подписи шифруются ChaCha20-Poly1305; подписи Ed25519 покрывают
//! транскрипт. PQ KEM применяется только эфемерно: public key/ciphertext
//! входят в m1/m2, а общий секрет смешивается в chaining key через HKDF.
//! Ноль аллокаций: все сообщения и состояние — на буферах и в стеке.
//! Эфемеральные ключи задаёт вызывающий сидами.
//!
//! Это гибридный режим: классическая безопасность сохраняется, если ML-KEM
//! будет скомпрометирован, а постквантовая конфиденциальность — если X25519
//! будет взломан. Аутентификация по-прежнему использует существующие Ed25519
//! identity keys; полноценная PQ-аутентификация требует отдельного изменения
//! identity bundle и не подменяется этим KEX.
//!
//! Раскладка сообщений:
//!   m1 = e1_pub || init enc_pk || mlkem_pk             (1248)
//!   m2 = e2_pub || mlkem_ct || box(resp_pk || sig_r)   (1232)
//!   m3 = box(init_pk || sig_i)                          (112)
//!
//! Последовательность MixKey (одинакова у сторон):
//!   h0 = ck0 = BLAKE2s256("shopot-hs-v5-pq")
//!   h1 = H(h0||m1);  h2 = H(h1||e2)
//!   ee = X25519(e2,e1) -> k1, ck;  pq = ML-KEM(m1_pk) -> ck
//!   sig_r = Sign_r(h2);  box1 = Seal(k1, n=0, ad=h2)
//!   h3 = H(h2||mlkem_ct||box1);  es = X25519(s_r,e1) -> k2, ck
//!   sig_i = Sign_i(h3);  box2 = Seal(k2, n=1, ad=h3);  h4 = H(h3||box2)
//!   se = X25519(s_i,e2) -> ck
//!   (send_key, recv_key) = HKDF-Expand(ck, "shopot-hs-finish-v5")
//!
//! sig_r покрывает h2 (весь m1, включая mlkem_pk инициатора); sig_i
//! покрывает h3 (mlkem_ct ответчика + box1). Подмена любого PQ-поля
//! ломает подпись или ключи — тайп-чекинга «вслепую» нет.

const std = @import("std");

const identity = @import("identity.zig");
const aead = @import("aead.zig");

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const X25519 = std.crypto.dh.X25519;
const MlKem768 = std.crypto.kem.ml_kem.MLKem768;
const Ed25519 = std.crypto.sign.Ed25519;
const Blake2s256 = std.crypto.hash.blake2.Blake2s256;

/// Домен-версия протокола. v5-pq: гибрид X25519+ML-KEM-768 (§ PROTOCOL.md).
/// Домен входит в цепной ключ рукопожатия: ядра разных версий НЕ сходятся
/// вовсе (боксы m2/m3 не открываются) — fail-fast вместо молчаливого
/// даунгрейда; несовместимое изменение = новая версия в домене.
const domain = "shopot-hs-v5-pq";
const mix_info = "shopot-hs-mix-v5";
const finish_info = "shopot-hs-finish-v5";
const kem_seed_domain = "shopot-hs-mlkem-seed-v1";
const kem_encap_domain = "shopot-hs-mlkem-encap-v1";

const payload_len = 32 + 64; // статический ключ || подпись Ed25519
const kem_pk_len = MlKem768.PublicKey.encoded_length;
const kem_ct_len = MlKem768.ciphertext_length;
const kem_seed_len = MlKem768.seed_length;

/// Длина m1: e1_pub (32) || init enc_pk (32) || ML-KEM-768 public key.
/// enc_pk идёт открытым текстом только для маршрутизации responder-а.
pub const m1_len = 32 + 32 + kem_pk_len;

/// Длина m2: e2_pub (32) || ML-KEM-768 ciphertext || encrypted identity box.
pub const m2_len = 32 + kem_ct_len + payload_len + aead.tag_length;

/// Длина m3: encrypted identity box (payload_len + tag).
pub const m3_len = payload_len + aead.tag_length;

/// Длина подписи Ed25519.
pub const sig_len = 64;

/// Ошибки рукопожатия.
pub const Error = error{
    /// Неверная длина сообщения.
    BadLength,
    /// AEAD не открылся (чужие эфемерки, битые байты, вырожденный DH).
    Tampered,
    /// Подпись транскрипта не сошлась.
    BadSignature,
    /// Статический ключ X25519 в боксе не равен ожидаемому из bundle
    /// контакта (привязка личности к статике; практика libp2p-noise:
    /// приложение обязано проверить remote static после XX).
    KeyMismatch,
    /// Вырожденный сид ML-KEM (практически недостижим для CSPRNG-сида).
    KemKeygen,
};

/// Сессионные ключи; send/recv зеркальны у двух сторон.
pub const SessionKeys = struct {
    /// Ключ шифрования исходящих сообщений.
    send_key: [32]u8,
    /// Ключ расшифровки входящих сообщений.
    recv_key: [32]u8,
    /// Финальный хэш транскрипта (совпадает у сторон).
    transcript: [32]u8,
};

/// BLAKE2s-256 над конкатенацией частей.
fn hashParts(parts: []const []const u8) [32]u8 {
    var h = Blake2s256.init(.{});
    for (parts) |p| h.update(p);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

/// Сид ML-KEM-пар инициатора: HKDF(eph_seed, домен) — отдельный домен,
/// чтобы X25519-скаляр и ML-KEM-сид не коррелировали.
fn deriveKemSeed(eph_seed: [32]u8) [kem_seed_len]u8 {
    var seed: [kem_seed_len]u8 = undefined;
    HkdfSha256.expand(&seed, kem_seed_domain, eph_seed);
    return seed;
}

/// Сид инкапсуляции ответчика: BLAKE2s(домен || eph_seed || m1) — привязка
/// к конкретному m1 исключает переиспользование рандомности инкапсуляции
/// между разными инициаторами при одном и том же eph_seed.
fn deriveEncapSeed(eph_seed: [32]u8, m1: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    var h = Blake2s256.init(.{});
    h.update(kem_encap_domain);
    h.update(&eph_seed);
    h.update(m1);
    h.final(&digest);
    return digest;
}

/// MixKey: (ck, key) = HKDF(ck, ikm); ck обновляется на месте, возвращается
/// новый ключ шифрования.
fn mixKey(ck: *[32]u8, ikm: []const u8) [32]u8 {
    var prk = HkdfSha256.extract(ck, ikm);
    var okm: [64]u8 = undefined;
    HkdfSha256.expand(&okm, mix_info, prk);
    std.crypto.secureZero(u8, &prk);

    ck.* = okm[0..32].*;
    const key = okm[32..64].*;
    @memset(okm[32..64], 0);
    return key;
}

/// Подписывает `transcript` парой Ed25519 личности (пара кэшируется в
/// Identity с fromSeed — повторного скалярного вывода нет). Ошибки
/// подписи схлопнуты в error.Tampered: для валидной личности недостижимы.
fn signTranscript(id: *const identity.Identity, transcript: [32]u8, sig_out: *[sig_len]u8) error{Tampered}!void {
    id.sign(&transcript, sig_out) catch return error.Tampered;
}

/// Инициатор (первый в рукопожатии).
pub const Initiator = struct {
    h: [32]u8,
    ck: [32]u8,
    eph_secret: [32]u8,
    kem_secret: MlKem768.SecretKey,
    my_id: *const identity.Identity,

    /// Начинает гибридное рукопожатие: m1 содержит X25519-паблик,
    /// enc_pk и ephemeral ML-KEM-768 public key. Оба эфемерных ключа
    /// детерминированы из `eph_seed` (для тестов); в проде eph_seed
    /// обязан приходить из CSPRNG — сид определяет обе пары.
    pub fn start(out_m1: *[m1_len]u8, my_id: *const identity.Identity, eph_seed: [32]u8) Error!Initiator {
        var h0: [32]u8 = undefined;
        Blake2s256.hash(domain, &h0, .{});

        const eph = X25519.KeyPair.generateDeterministic(eph_seed);
        const kem_seed = deriveKemSeed(eph_seed);
        const kem = MlKem768.KeyPair.generateDeterministic(kem_seed) catch return error.KemKeygen;
        const kem_pk = kem.public_key.toBytes();
        out_m1[0..32].* = eph.public_key;
        out_m1[32..64].* = my_id.enc_public;
        @memcpy(out_m1[64..][0..kem_pk_len], &kem_pk);
        return .{
            .h = hashParts(&[_][]const u8{ &h0, out_m1 }),
            .ck = h0,
            .eph_secret = eph.secret_key,
            .kem_secret = kem.secret_key,
            .my_id = my_id,
        };
    }

    /// Обрабатывает m2 (проверяет sig по `peer_sign_public`, сверяет
    /// статический ключ с `peer_enc_public`, если тот известен), пишет m3,
    /// возвращает сессионные ключи. Сверка статики закрывает разрыв
    /// «sig покрывает транскрипт до бокса»: без неё сессионный ключ мог
    /// быть выведен с чужой статикой, не равной bundle контакта.
    pub fn recv2(self: *Initiator, out_m3: *[m3_len]u8, m2: []const u8, peer_sign_public: [32]u8, peer_enc_public: ?[32]u8) Error!SessionKeys {
        if (m2.len != m2_len) return error.BadLength;

        const e2_public: [32]u8 = m2[0..32].*;
        const kem_ct = m2[32..][0..kem_ct_len];
        const box1: []const u8 = m2[32 + kem_ct_len ..];

        // h2 = H(h1||e2)
        self.h = hashParts(&[_][]const u8{ &self.h, &e2_public });

        // ee = X25519(e_i, e_r) -> k1
        const ee = X25519.scalarmult(self.eph_secret, e2_public) catch return error.Tampered;
        const k1 = mixKey(&self.ck, &ee);

        // pq = ML-KEM-деинкапсуляция в цепной ключ (порядок ee -> pq -> es
        // -> se одинаков у сторон). Подмена ct даёт другой секрет: ML-KEM
        // отвечает неявным отказом (псевдослучайный ключ), ключи
        // расходятся и m3 у ответчика не открывается.
        const kem_ss = self.kem_secret.decaps(kem_ct) catch return error.Tampered;
        _ = mixKey(&self.ck, &kem_ss);

        // открыть box1: resp_enc_pk || sig_r (ad = h2)
        var payload: [payload_len]u8 = undefined;
        aead.open(&payload, box1, k1, aead.nonceFor(0), &self.h) catch return error.Tampered;
        const resp_enc_public: [32]u8 = payload[0..32].*;
        const sig_r: [sig_len]u8 = payload[32..payload_len].*;
        @memset(&payload, 0);

        // статический ключ обязан совпадать с известным bundle контакта
        if (peer_enc_public) |expected| {
            if (!std.mem.eql(u8, &resp_enc_public, &expected)) return error.KeyMismatch;
        }

        // подпись ответчика над транскриптом h2
        try identity.Identity.verify(peer_sign_public, &self.h, sig_r);

        // транскрипт после m2: хвост m2 (mlkem_ct || box1) целиком —
        // зеркально ответчику, который хэширует out_m2[32..]
        self.h = hashParts(&[_][]const u8{ &self.h, m2[32..] });
        const h3 = self.h;

        // es = X25519(e_i, s_r) -> k2
        const es = X25519.scalarmult(self.eph_secret, resp_enc_public) catch return error.Tampered;
        const k2 = mixKey(&self.ck, &es);

        // m3: box(init_enc_pk || sig_i), ad = h3
        var payload3: [payload_len]u8 = undefined;
        payload3[0..32].* = self.my_id.enc_public;
        try signTranscript(self.my_id, h3, payload3[32..payload_len]);
        aead.seal(out_m3, &payload3, k2, aead.nonceFor(1), &h3);
        @memset(&payload3, 0);

        // транскрипт после m3
        self.h = hashParts(&[_][]const u8{ &h3, out_m3 });

        // se = X25519(s_i, e_r) -> ck
        const se = X25519.scalarmult(self.my_id.enc_secret, e2_public) catch return error.Tampered;
        _ = mixKey(&self.ck, &se);

        return finishKeys(self.ck, self.h, .initiator);
    }
};

/// Ответчик.
pub const Responder = struct {
    h: [32]u8,
    ck: [32]u8,
    k2: [32]u8,
    e2_secret: [32]u8,
    my_id: *const identity.Identity,

    /// Обрабатывает m1, пишет m2 (эфемерный X25519 и ML-KEM-инкапсуляцию
    /// из `eph_seed`; sig подписывается сидом Ed25519 из `my_id`).
    pub fn recv1(out_m2: *[m2_len]u8, my_id: *const identity.Identity, m1: []const u8, eph_seed: [32]u8) Error!Responder {
        if (m1.len != m1_len) return error.BadLength;

        var h0: [32]u8 = undefined;
        Blake2s256.hash(domain, &h0, .{});

        const e1_public: [32]u8 = m1[0..32].*;
        const kem_pk_bytes = m1[64..][0..kem_pk_len];
        const kem_pk = MlKem768.PublicKey.fromBytes(kem_pk_bytes) catch return error.Tampered;
        const kem_seed = deriveEncapSeed(eph_seed, m1);
        const kem = kem_pk.encapsDeterministic(&kem_seed);

        // транскрипт покрывает весь m1 (включая enc_pk и mlkem_pk
        // инициатора): подмена любого байта меняет ключи и роняет подпись
        var self = Responder{
            .h = hashParts(&[_][]const u8{ &h0, m1 }),
            .ck = h0,
            .k2 = undefined,
            .e2_secret = undefined,
            .my_id = my_id,
        };

        const e2 = X25519.KeyPair.generateDeterministic(eph_seed);
        self.e2_secret = e2.secret_key;

        // h2 = H(h1||e2)
        self.h = hashParts(&[_][]const u8{ &self.h, &e2.public_key });

        // ee = X25519(e_r, e_i) -> k1
        const ee = X25519.scalarmult(self.e2_secret, e1_public) catch return error.Tampered;
        const k1 = mixKey(&self.ck, &ee);

        // pq = ML-KEM-общий секрет в цепной ключ (тот же порядок, что у
        // инициатора: ee -> pq -> es -> se)
        _ = mixKey(&self.ck, &kem.shared_secret);

        // m2: e2_pub || mlkem_ct || box(resp_enc_pk || sig_r), ad = h2
        var payload: [payload_len]u8 = undefined;
        payload[0..32].* = my_id.enc_public;
        try signTranscript(my_id, self.h, payload[32..payload_len]);
        out_m2[0..32].* = e2.public_key;
        @memcpy(out_m2[32..][0..kem_ct_len], &kem.ciphertext);
        aead.seal(out_m2[32 + kem_ct_len ..], &payload, k1, aead.nonceFor(0), &self.h);
        @memset(&payload, 0);

        // транскрипт после m2: mlkem_ct + box1 хвостом целиком
        self.h = hashParts(&[_][]const u8{ &self.h, out_m2[32..] });

        // es = X25519(s_r, e_i) -> k2 (ключ статики инициатора в m3)
        const es = X25519.scalarmult(my_id.enc_secret, e1_public) catch return error.Tampered;
        self.k2 = mixKey(&self.ck, &es);

        return self;
    }

    /// Обрабатывает m3. peer_sign_public == null — режим pending-join:
    /// подпись НЕ проверяется (контакт неизвестен), личность доказывается
    /// JOIN-конвертом поверх сессии; peer_enc_public == null — то же для
    /// сверки статики. Для известного контакта оба значения передаются из
    /// bundle. Возвращает сессионные ключи.
    pub fn recv3(self: *Responder, m3: []const u8, peer_sign_public: ?[32]u8, peer_enc_public: ?[32]u8) Error!SessionKeys {
        if (m3.len != m3_len) return error.BadLength;

        // открыть box2: init_enc_pk || sig_i (ad = h3)
        var payload: [payload_len]u8 = undefined;
        aead.open(&payload, m3, self.k2, aead.nonceFor(1), &self.h) catch return error.Tampered;
        const init_enc_public: [32]u8 = payload[0..32].*;
        const sig_i: [sig_len]u8 = payload[32..payload_len].*;
        @memset(&payload, 0);

        // статический ключ обязан совпадать с известным bundle контакта
        if (peer_enc_public) |expected| {
            if (!std.mem.eql(u8, &init_enc_public, &expected)) return error.KeyMismatch;
        }

        // подпись инициатора над транскриптом h3
        if (peer_sign_public) |pk| {
            try identity.Identity.verify(pk, &self.h, sig_i);
        }

        // транскрипт после m3
        self.h = hashParts(&[_][]const u8{ &self.h, m3 });

        // se = X25519(s_r, s_i) -> ck
        const se = X25519.scalarmult(self.e2_secret, init_enc_public) catch return error.Tampered;
        _ = mixKey(&self.ck, &se);

        return finishKeys(self.ck, self.h, .responder);
    }
};

const Side = enum { initiator, responder };

/// Разворачивает финальный ck в зеркальные пары ключей.
fn finishKeys(ck: [32]u8, transcript: [32]u8, side: Side) SessionKeys {
    var okm: [64]u8 = undefined;
    HkdfSha256.expand(&okm, finish_info, ck);
    const k_i2r = okm[0..32].*; // поток инициатор -> ответчик
    const k_r2i = okm[32..64].*; // поток ответчик -> инициатор
    @memset(&okm, 0);

    return switch (side) {
        .initiator => .{ .send_key = k_i2r, .recv_key = k_r2i, .transcript = transcript },
        .responder => .{ .send_key = k_r2i, .recv_key = k_i2r, .transcript = transcript },
    };
}
