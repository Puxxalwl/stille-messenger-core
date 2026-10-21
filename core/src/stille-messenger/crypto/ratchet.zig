//! Симметричный рэтчет: шаг сообщения эволюционирует цепочку
//! (msg_key = HKDF-Expand(ck, "shopot-msg-v3" || u64 LE counter),
//! затем ck = HMAC-SHA256(ck, 0x02)), DH-шаг пересоздаёт обе цепочки из
//! X25519 (root = HKDF(shared, "shopot-ratchet-v3")). Приём разделён на
//! peekRecv (вывод ключа ОЖИДАЕМОГО кадра без сдвига цепочки) и commitRecv
//! (сдвиг после успешной расшифровки) — по Double Ratchet spec §3.5/§8.10.
//! Направления делятся
//! детерминированно: сторона с лексикографически меньшим публичным ключом
//! шлёт по цепочке HMAC(root, 0x03) и принимает по HMAC(root, 0x04),
//! противоположная — наоборот; обе стороны получают одинаковые значения
//! chain_send/chain_recv, зеркальные по направлениям.

const std = @import("std");

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const X25519 = std.crypto.dh.X25519;

const msg_info = "shopot-msg-v3";
const ratchet_salt = "shopot-ratchet-v3";

/// Ошибки рэтчета: вырожденный публичный ключ удалённой стороны.
pub const Error = error{BadRemoteKey};

pub const Ratchet = struct {
    /// Цепочка исходящих сообщений.
    chain_send: [32]u8,
    /// Цепочка входящих сообщений.
    chain_recv: [32]u8,
    /// Счётчик следующего исходящего сообщения (уходит в nonce AEAD).
    send_counter: u64,
    /// Счётчик следующего входящего сообщения.
    recv_counter: u64,
    /// Номер эпохи (0 из handshake, +1 на каждый dhStep). Уходит в заголовок
    /// sealed-кадра: приёмник выбирает цепочку по эпохе, кадры предыдущей
    /// эпохи в полёте расшифровываются по снапшоту цепочки у сессии.
    epoch: u16 = 0,

    /// Собирает рэтчет из начальных цепочек (обычно из handshake).
    pub fn init(chain_send: [32]u8, chain_recv: [32]u8) Ratchet {
        return .{
            .chain_send = chain_send,
            .chain_recv = chain_recv,
            .send_counter = 0,
            .recv_counter = 0,
            .epoch = 0,
        };
    }

    /// Выводит ключ исходящего сообщения в `msg_key` и возвращает счётчик
    /// nonce для aead.nonceFor; затем сдвигает цепочку отправки.
    pub fn stepSend(self: *Ratchet, msg_key: *[32]u8) u64 {
        const counter = self.send_counter;
        self.send_counter += 1;
        messageKey(self.chain_send, counter, msg_key);
        stepChain(&self.chain_send);
        return counter;
    }

    /// Выводит ключ ОЖИДАЕМОГО входящего сообщения в `msg_key` и возвращает
    /// его счётчик, НЕ сдвигая цепочку приёма: цепочка обязана сдвигаться
    /// только после УСПЕШНОЙ расшифровки кадра (commitRecv), иначе один
    /// битый кадр навсегда рассинхронизирует стороны (см. spec Double
    /// Ratchet, §3.5: ключ выводится под конкретный номер сообщения).
    /// Зеркален stepSend при том же состоянии цепочки.
    pub fn peekRecv(self: *const Ratchet, msg_key: *[32]u8) u64 {
        messageKey(self.chain_recv, self.recv_counter, msg_key);
        return self.recv_counter;
    }

    /// Сдвигает цепочку приёма и счётчик после успешной расшифровки кадра,
    /// выведенного через peekRecv. Повторный вызов без peek — ошибка
    /// программирования (рассинхронизация), поэтому сдвиг необратим.
    pub fn commitRecv(self: *Ratchet) void {
        stepChain(&self.chain_recv);
        self.recv_counter += 1;
    }

    /// DH-шаг (PCS-ротация): обе цепочки пересоздаются из X25519(
    /// `own_secret`, `new_remote_pub`), счётчики сбрасываются, эпоха +1.
    /// В ротации `own_secret` — СВЕЖАЯ ключевая пара стороны (не статика
    /// личности): обе стороны обмениваются свежими пабликами в конвертах
    /// RATCHET_KEY и зовут dhStep с зеркальными аргументами — общий секрет
    /// DH(a_fresh, b_fresh) каждый раз новый. Направление "03" назначается
    /// стороне с меньшим публичным ключом (детерминированное правило,
    /// одинаковое у обеих сторон), поэтому chain_send одной стороны всегда
    /// совпадает с chain_recv другой.
    pub fn dhStep(self: *Ratchet, new_remote_pub: [32]u8, own_secret: [32]u8) Error!void {
        var shared = X25519.scalarmult(own_secret, new_remote_pub) catch return error.BadRemoteKey;
        var root = HkdfSha256.extract(ratchet_salt, &shared);
        std.crypto.secureZero(u8, &shared);

        const s3 = [_]u8{0x03};
        const s4 = [_]u8{0x04};
        var c3: [32]u8 = undefined;
        var c4: [32]u8 = undefined;
        HmacSha256.create(&c3, &s3, &root);
        HmacSha256.create(&c4, &s4, &root);
        std.crypto.secureZero(u8, &root);

        const own_public = X25519.recoverPublicKey(own_secret);
        if (std.mem.order(u8, &own_public, &new_remote_pub) != .gt) {
            self.chain_send = c3;
            self.chain_recv = c4;
        } else {
            self.chain_send = c4;
            self.chain_recv = c3;
        }
        @memset(&c3, 0);
        @memset(&c4, 0);

        self.send_counter = 0;
        self.recv_counter = 0;
        self.epoch +%= 1;
    }

    /// Выводит ключ сообщения для ПРОИЗВОЛЬНОЙ цепочки и счётчика — для
    /// расшифровки кадров предыдущей эпохи по снапшоту цепочки (сессия
    /// хранит его на время ротации). Текущая эпоха идёт через
    /// peekRecv/commitRecv.
    pub fn deriveKey(chain: [32]u8, counter: u64, msg_key: *[32]u8) void {
        messageKey(chain, counter, msg_key);
    }

    /// Сдвигает ПРОИЗВОЛЬНУЮ цепочку (снапшот предыдущей эпохи у сессии)
    /// после успешной расшифровки кадра той эпохи.
    pub fn stepChainForward(chain: *[32]u8) void {
        stepChain(chain);
    }
};

/// msg_key = HKDF-Expand(chain, "shopot-msg-v3" || u64 LE counter).
fn messageKey(chain: [32]u8, counter: u64, out: *[32]u8) void {
    var info: [msg_info.len + 8]u8 = undefined;
    @memcpy(info[0..msg_info.len], msg_info);
    std.mem.writeInt(u64, info[msg_info.len..][0..8], counter, .little);
    HkdfSha256.expand(out, &info, chain);
}

/// ck = HMAC-SHA256(ck, 0x02), старое значение обнуляется.
fn stepChain(chain: *[32]u8) void {
    var next: [32]u8 = undefined;
    const input = [_]u8{0x02};
    HmacSha256.create(&next, &input, chain);
    std.crypto.secureZero(u8, chain);
    chain.* = next;
}
