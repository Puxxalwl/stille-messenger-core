//! envelope — бинарные конверты протокола v3 (без JSON).
//!
//! Кадр: тег (u8), затем поля little-endian (см. codec.zig). Поля переменной
//! длины (тело TEXT, аудио CALL_AUDIO) имеют префикс длины u16. Декодер
//! возвращает union с типизированными полями; аллокаций нет — срезы `body`/
//! `data` указывают во входной буфер.
//!
//! Раскладка кадров:
//!   TEXT          0x10: msg_id: [16]u8, ts_ms: u64, body: u16 + байты (≤ 4096),
//!                       ents: u8-счётчик + записи форматирования (см. TextEntity)
//!   REPLY_TEXT    0x11: msg_id: [16]u8, ts_ms: u64, reply_to: [16]u8,
//!                       body: u16 + байты, ents: u8-счётчик + записи
//!   ACK           0x15: msg_id: [16]u8
//!   REACT         0x13: msg_id: [16]u8, op: u8, code: u32 (unicode code point)
//!   BLOCK_NOTICE  0x14: reason: u8
//!   PRESENCE_PING 0x20: seq: u32, ts_ms: u64
//!   PRESENCE_PONG 0x21: seq: u32, ts_peer_ms: u64
//!   CALL_SIGNAL   0x30: op: u8, call_id: [16]u8
//!   CALL_AUDIO    0x31: seq: u32, data: u16 + байты (≤ 1024)
//!   JOIN          0x40: bundle: [64]u8, name: u8 + байты (≤ 32),
//!                       sig: [64]u8, hmac: [32]u8
//!   PROFILE       0x42: name: u8 + байты (≤ 32), avatar_id: [16]u8
//!   CONTACT_CARD  0x43: name: u8 + байты (≤ 32), bundle: [64]u8,
//!                       addr: u16 + байты (≤ 64, пусто = неизвестен)
//!   RATCHET_KEY   0x44: epoch: u16, dh_pub: [32]u8 (PCS-ротация рэтчета)
//!   PUNCH_CANDIDATES 0x47: count u8 (1..8), записи × {type u8 (0 host /
//!                       1 reflexive), ip 4 октета, port u16} — кандидаты
//!                       прямого пути отправителя (NAT-punch; обмен внутри
//!                       аутентифицированной сессии, старые ядра пропускают)
//!   AVATAR        0x50: avatar_id: [16]u8, data: u16 + байты (≤ 16000)
//!   AVATAR_ACK   0x51: avatar_id: [16]u8
//!   AVATAR_REQ   0x52: avatar_id: [16]u8
//!   FILE_ACK     0x62: file_id: [16]u8, got: u32 (докачка)

const std = @import("std");
const codec = @import("codec.zig");

/// Теги кадров протокола v3.
pub const Tag = enum(u8) {
    /// Текстовое сообщение.
    text = 0x10,
    /// Ответ на текстовое сообщение.
    reply_text = 0x11,
    /// Реакция на сообщение.
    react = 0x13,
    /// Уведомление о блокировке.
    block_notice = 0x14,
    /// ACK доставки TEXT (высылается получателем каждого сообщения).
    ack = 0x15,
    /// Пинг присутствия.
    presence_ping = 0x20,
    /// Ответ на пинг присутствия.
    presence_pong = 0x21,
    /// Сигнальное сообщение звонка.
    call_signal = 0x30,
    /// Аудиокадр звонка.
    call_audio = 0x31,
    /// JOIN: предъявление одностороннего инвайта (HMAC по секрету кода).
    join = 0x40,
    /// PROFILE: имя и текущий avatar_id отправителя (эхо при каждом
    /// установлении сессии).
    profile = 0x42,
    /// CONTACT_CARD: визитная карточка третьего лица (имя + bundle +
    /// известный адрес) — SEND_CONTACT. Неизвестный тег на приёме
    /// отбрасывается: старые ядра просто пропускают карточку.
    contact_card = 0x43,
    /// RATCHET_KEY: свежий публичный X25519-ключ отправителя для DH-шага
    /// рэтчета. Обрабатывается сессией (до движка): обмен пабликами обеих
    /// сторон завершается совместным dhStep — новые цепочки, эпоха +1.
    ratchet_key = 0x44,
    /// AVATAR: байты аватара (контент-адресованы SHA-256[0..16]).
    avatar = 0x50,
    /// AVATAR_ACK: аватар получен и сохранён.
    avatar_ack = 0x51,
    /// AVATAR_REQ: просьба переслать аватар с этим id.
    avatar_req = 0x52,
    /// SYNC: партия записей БД для репликации на устройство того же
    /// пользователя (device_sync). Каждая запись аутентифицируется
    /// HMAC-SHA256 над ключом синхронизации (выводится из сида личности);
    /// чужая сторона подделать записи не может — неизвестные теги на
    /// приёме отбрасываются, как у CONTACT_CARD.
    sync = 0x45,
    /// SYNC_ACK: партия применена (или осознанно пропущена) получателем.
    sync_ack = 0x46,
    /// PUNCH_CANDIDATES: кандидаты прямого пути отправителя (NAT-punch,
    /// 2.9.0). Обмен идёт внутри аутентифицированной AEAD-сессии —
    /// подмена/подсовывание кандидатов извне невозможно, replay
    /// отсечён счётчиками сессии. Старые ядра кадр отбрасывают
    /// (неизвестный тег), новый прямой путь у них не поднимается —
    /// соединение остаётся на relay.
    punch = 0x47,
    /// V6_ADDR (2.10.0): глобальные IPv6-адреса отправителя + его
    /// listen-порт — прямые адреса без NAT. Отправляется при бинде
    /// relay-сессии: пир запоминает как контакт-адрес для прямого
    /// автодозвона. Старые ядра тег не знают — пропускают, остаются
    /// на релее. Только внутри аутентифицированной сессии.
    v6addr = 0x48,
    file_meta = 0x60,
    file_data = 0x61,
    /// FILE_ACK: сколько чанков файла уже принято (докачка с этой позиции).
    file_ack = 0x62,
};

/// Максимум длины имени в JOIN.
pub const max_join_name = 32;
/// Длина Ed25519-подписи в JOIN.
pub const join_sig_len = 64;
/// Длина HMAC-SHA256 в JOIN.
pub const join_hmac_len = 32;

/// REACT.op: добавить реакцию.
pub const react_add: u8 = 1;
/// REACT.op: снять реакцию.
pub const react_remove: u8 = 2;

/// CALL_SIGNAL.op: предложение звонка.
pub const call_offer: u8 = 0;
/// CALL_SIGNAL.op: принятие звонка.
pub const call_accept: u8 = 1;
/// CALL_SIGNAL.op: отклонение звонка.
pub const call_reject: u8 = 2;
/// CALL_SIGNAL.op: завершение звонка.
pub const call_end: u8 = 3;

/// Длина идентификаторов (msg_id, call_id).
pub const id_len = 16;
/// Максимум длины тела TEXT.
pub const max_text_body = 4096;
const entities = @import("entities.zig");

/// Максимум длины DATA в CALL_AUDIO.
pub const max_audio_data = 1024;
/// Максимум данных AVATAR: влезает в один obf-кадр класса 16384.
pub const max_avatar_data = 16000;
pub const max_file_chunk = 16000;
pub const max_file_name = 64;
/// Максимум длины имени в CONTACT_CARD.
pub const max_card_name = 32;
/// Максимум длины адреса в CONTACT_CARD (host:port).
pub const max_card_addr = 64;
/// Максимум записей в одной партии SYNC.
pub const max_sync_recs = 64;
/// Максимум данных одной записи SYNC (payload записи БД).
pub const max_sync_rec_data = 4096;
/// Длина HMAC-SHA256 записи SYNC.
pub const sync_mac_len = 32;
/// Максимум хвоста записей SYNC (влезает в один кадр с запасом до
/// max_encoded_len).
pub const max_sync_tail = 16000;

/// Максимальная длина закодированного кадра (AVATAR с телом 16000).
pub const max_encoded_len = 1 + id_len + 4 + 2 + max_file_chunk;

// entities форматирования: выделено в entities.zig (порядок байтов —
// контракт v4); переэкспорт для стабильности api модуля
pub const EntityKind = entities.EntityKind;
pub const TextEntity = entities.TextEntity;
pub const EntitiesError = entities.EntitiesError;
pub const validateEntities = entities.validateEntities;
pub const encodeEntitiesTail = entities.encodeEntitiesTail;
pub const parseEntities = entities.parseEntities;
pub const max_text_entities = entities.max_text_entities;
pub const max_entity_value = entities.max_entity_value;
pub const max_text_tail = entities.max_text_tail;

pub const SyncRecView = struct {
    /// Семантика записи — enum u8 модуля app/sync.zig; конверт проверяет
    /// только структуру, а не значение.
    kind: u8,
    /// HMAC-SHA256(sync_key, kind || data).
    mac: [sync_mac_len]u8,
    /// Payload записи (переведённый формат лога: cid → bundle).
    data: []const u8,
};

/// Ошибки разбора хвоста SYNC.
pub const SyncRecsError = error{
    /// Хвост обрезан.
    Truncated,
    /// Лишние байты после последней записи.
    BadLen,
    /// count > max_sync_recs или data записи > max_sync_rec_data.
    TooBig,
};

/// Разобрать и провалидировать хвост SYNC: ровно `count` записей
/// {[kind u8][mac 32][len u16][data]} с полным потреблением байтов.
/// Заполняет `out` (если задан); возвращает разобранное число записей.
pub fn parseSyncRecs(bytes: []const u8, count: usize, out: ?[]SyncRecView) SyncRecsError!usize {
    if (count > max_sync_recs) return error.TooBig;
    var pos: usize = 0;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        if (bytes.len - pos < 1 + sync_mac_len + 2) return error.Truncated;
        const kind = bytes[pos];
        var mac: [sync_mac_len]u8 = undefined;
        @memcpy(&mac, bytes[pos + 1 ..][0..sync_mac_len]);
        pos += 1 + sync_mac_len;
        const len = std.mem.readInt(u16, bytes[pos..][0..2], .little);
        pos += 2;
        if (len > max_sync_rec_data) return error.TooBig;
        if (bytes.len - pos < len) return error.Truncated;
        const data = bytes[pos .. pos + len];
        pos += len;
        if (out) |o| o[i] = .{ .kind = kind, .mac = mac, .data = data };
    }
    if (pos != bytes.len) return error.BadLen;
    return count;
}

/// TEXT (0x10): текстовое сообщение.
pub const Text = struct {
    /// Идентификатор сообщения.
    msg_id: [id_len]u8,
    /// Метка времени отправителя, мс.
    ts_ms: u64,
    /// Тело сообщения, ≤ 4096 байтов; срез входного буфера после decode.
    body: []const u8,
    /// Хвост форматирования: [count u8] × {entity} (см. encodeEntitiesTail /
    /// parseEntities). У отправителя — срез буфера вызывающего, построенный
    /// encodeEntitiesTail (encode валидирует его перед отправкой); пустой
    /// срез = форматирования нет (на проводе всё равно уйдёт байт счётчика
    /// ноль). У получателя — срез входного буфера, уже провалидирован decode.
    ents_tail: []const u8 = &.{},
};

/// REPLY_TEXT (0x11): ответ на существующее сообщение.
pub const ReplyText = struct {
    /// Идентификатор нового сообщения.
    msg_id: [id_len]u8,
    /// Метка времени отправителя, мс.
    ts_ms: u64,
    /// Идентификатор сообщения, на которое отвечают.
    reply_to: [id_len]u8,
    /// Тело ответа, ≤ 4096 байтов.
    body: []const u8,
    /// Канонический хвост entities; пустой срез кодируется счётчиком 0.
    ents_tail: []const u8 = &.{},
};

/// REACT (0x13): реакция на сообщение.
pub const React = struct {
    /// Идентификатор сообщения.
    msg_id: [id_len]u8,
    /// 1 = добавить, 2 = снять (см. react_add/react_remove).
    op: u8,
    /// Реакция — unicode code point (U+0000..U+10FFFF), например 0x2764 = ❤.
    /// u32 LE в проводе; рендер (глиф/эмодзи) — задача клиента.
    code: u32,
};

/// ACK (0x15): подтверждение доставки TEXT с этим msg_id.
pub const Ack = struct {
    /// Идентификатор доставленного сообщения.
    msg_id: [id_len]u8,
};

/// BLOCK_NOTICE (0x14): уведомление о блокировке.
pub const BlockNotice = struct {
    /// Код причины блокировки.
    reason: u8,
};

/// PRESENCE_PING (0x20): пинг присутствия.
pub const PresencePing = struct {
    /// Порядковый номер пинга.
    seq: u32,
    /// Метка времени отправителя, мс.
    ts_ms: u64,
};

/// PRESENCE_PONG (0x21): ответ на пинг присутствия.
pub const PresencePong = struct {
    /// Порядковый номер из пинга.
    seq: u32,
    /// Метка времени пира, мс.
    ts_peer_ms: u64,
};

/// CALL_SIGNAL (0x30): сигнальное сообщение звонка.
pub const CallSignal = struct {
    /// 0 = offer, 1 = accept, 2 = reject, 3 = end (см. call_* константы).
    op: u8,
    /// Идентификатор звонка.
    call_id: [id_len]u8,
};

/// CALL_AUDIO (0x31): аудиокадр звонка.
pub const CallAudio = struct {
    /// Порядковый номер кадра.
    seq: u32,
    /// Полезная нагрузка, ≤ 1024 байтов; срез входного буфера после decode.
    data: []const u8,
};

/// PROFILE (0x42): имя и текущий avatar_id; отправляется ядром при каждом
/// установлении сессии, получатель обновляет имя контакта и знает, какой
/// аватар запрашивать (несовпадение id -> AVATAR_REQ).
pub const Profile = struct {
    /// Отображаемое имя отправителя, ≤ 32 байтов.
    name: []const u8,
    /// Текущий avatar_id отправителя; нули — аватара нет.
    avatar_id: [id_len]u8,
};

/// AVATAR (0x50): байты аватара (контент-адресованы id = SHA-256[0..16]).
pub const Avatar = struct {
    /// SHA-256(data)[0..16] — дедуп и адресация.
    avatar_id: [id_len]u8,
    /// Байты картинки, ≤ 16000; срез входного буфера после decode.
    data: []const u8,
};

/// AVATAR_ACK (0x51): аватар получен и сохранён.
pub const AvatarAck = struct {
    avatar_id: [id_len]u8,
};

/// AVATAR_REQ (0x52): просьба переслать аватар с этим id.
pub const AvatarReq = struct {
    avatar_id: [id_len]u8,
};

/// FILE_META (0x60): анонс передачи файла. file_id = SHA-256(файла)[0..16]
/// (контент-адресация, как у аватаров). Отправляется ДО чанков FILE_DATA.
pub const FileMeta = struct {
    file_id: [16]u8,
    /// Имя файла (UTF-8, без путей), <= 64 байтов.
    name: []const u8,
    /// Полный размер файла, байт.
    size: u32,
    /// SHA-256 всего файла: приём сверяет перед сохранением.
    sha: [32]u8,
};

/// FILE_DATA (0x61): чанк файла. Порядок задаёт seq (0..n-1); приём
/// собирает по порядку. Чанк <= max_file_chunk, каждый = один obf-кадр.
pub const FileData = struct {
    file_id: [16]u8,
    /// Номер чанка (порядковый, с нуля).
    seq: u32,
    /// Байты файла, <= max_file_chunk.
    data: []const u8,
};

/// CONTACT_CARD (0x43): визитная карточка контакта, пересланная третьей
/// стороной (метод SEND_CONTACT). Получатель видит имя, bundle и (если
/// отправителю известен) адрес; чтобы ДОБАВИТЬ этого человека, нужен его
/// собственный инвайт-код — карточка знакомит, не подключает.
pub const ContactCard = struct {
    /// Отображаемое имя карточки, ≤ 32 байтов; срез входного буфера после decode.
    name: []const u8,
    /// Полный bundle владельца карточки: enc_pk || sign_pk.
    bundle: [64]u8,
    /// Последний известный адрес host:port, ≤ 64 байтов; пусто — неизвестен.
    addr: []const u8,
};

/// SYNC (0x45): партия записей БД устройства-близнеца (device_sync).
/// Хвост записей: count × {[kind u8][mac 32][len u16][data]}; mac =
/// HMAC-SHA256(sync_key, kind || record) — проверяет получатель, сверяя
/// перевод cid → bundle у записей с контактами (см. app/sync.zig).
/// Отправитель строит хвост готовым (wire-формат записей лога), приём
/// валидирует структуру decode'ом, семантику — parseSyncRecs.
pub const Sync = struct {
    /// Идентификатор парии: уникален в рамках отправителя; SYNC_ACK
    /// возвращает его же.
    batch_id: u32,
    /// Число записей в хвосте, ≤ max_sync_recs.
    count: u8,
    /// Хвост записей (готовые байты, ≤ max_sync_tail); срез входного буфера
    /// после decode / буфера вызывающего до encode.
    recs: []const u8,
};

/// SYNC_ACK (0x46): партия batch_id применена получателем.
pub const SyncAck = struct {
    batch_id: u32,
};

/// RATCHET_KEY (0x44): PCS-ротация рэтчета. Отправитель сгенерировал свежую
/// X25519-пару для следующей эпохи и предъявляет публичную часть; получив
/// паблики ОБЕИХ сторон, каждая выполняет dhStep (свежий секрет свой,
/// fresh-паблик чужой) — цепочки пересоздаются, компрометация старых
/// цепочек больше не читает новые сообщения.
pub const RatchetKey = struct {
    /// Эпоха, на которую предназначен ключ = ratchet.epoch + 1 отправителя.
    epoch: u16,
    /// Свежий публичный X25519-ключ отправителя.
    dh_pub: [32]u8,
};

/// FILE_ACK (0x62): подтверждение приёма докачки. Приёмник шлёт его в
/// ответ на FILE_META (позиция: 0 / ожидаемый seq / всего чанков, если файл
/// уже сохранён) и далее каждые N чанков; отправитель возобновляет передачу
/// с последнего подтверждения (got = следующий ожидаемый seq).
pub const FileAck = struct {
    file_id: [16]u8,
    /// Чанков принято (следующий ожидаемый seq).
    got: u32,
};

/// JOIN (0x40): держатель инвайт-кода доказывает право на подключение.
/// Отправляется первым конвертом сразу после рукопожатия.
pub const Join = struct {
    /// Полный bundle подключающегося: enc_pk || sign_pk.
    bundle: [64]u8,
    /// Имя подключающегося, ≤ 32 байтов; срез входного буфера после decode.
    name: []const u8,
    /// Ed25519-подпись подписавшего над transcript рукопожатия —
    /// связывает bundle с ключами сессии (анти-MITM).
    sig: [join_sig_len]u8,
    /// HMAC-SHA256(invite_secret, transcript) — доказательство держателя
    /// кода; сверяется по реестру секретов приглашающего.
    hmac: [join_hmac_len]u8,
};

/// Конверт протокола v3: один из семи кадров.
pub const Envelope = union(enum) {
    /// TEXT (0x10).
    text: Text,
    /// REPLY_TEXT (0x11).
    reply_text: ReplyText,
    /// REACT (0x13).
    react: React,
    /// BLOCK_NOTICE (0x14).
    block_notice: BlockNotice,
    /// ACK (0x15).
    ack: Ack,
    /// PRESENCE_PING (0x20).
    presence_ping: PresencePing,
    /// PRESENCE_PONG (0x21).
    presence_pong: PresencePong,
    /// CALL_SIGNAL (0x30).
    call_signal: CallSignal,
    /// CALL_AUDIO (0x31).
    call_audio: CallAudio,
    /// JOIN (0x40).
    join: Join,
    /// PROFILE (0x42).
    profile: Profile,
    /// CONTACT_CARD (0x43).
    contact_card: ContactCard,
    /// RATCHET_KEY (0x44).
    ratchet_key: RatchetKey,
    /// SYNC (0x45).
    sync: Sync,
    /// SYNC_ACK (0x46).
    sync_ack: SyncAck,
    /// PUNCH_CANDIDATES (0x47).
    punch: Punch,
    v6addr: V6Addr,
    /// AVATAR (0x50).
    avatar: Avatar,
    /// AVATAR_ACK (0x51).
    avatar_ack: AvatarAck,
    /// AVATAR_REQ (0x52).
    avatar_req: AvatarReq,
    file_meta: FileMeta,
    file_data: FileData,
    /// FILE_ACK (0x62).
    file_ack: FileAck,
};

/// Максимум кандидатов в PUNCH_CANDIDATES (бюджет кадра и движка).
pub const max_punch_candidates: usize = 8;
/// Тип записи кандидата: host — LAN ip:port листенера отправителя.
pub const punch_host: u8 = 0;
/// Тип записи кандидата: reflexive — публичный ip:port, каким relay
/// видит подключение отправителя (маппинг его NAT).
pub const punch_reflexive: u8 = 1;

/// PUNCH_CANDIDATES: фиксированный массив кандидатов + счётчик
/// (безаллокационный decode: срезов нет, значения копируются).
pub const Punch = struct {
    /// Число заполненных записей (1..max_punch_candidates).
    count: u8,
    /// Тип каждой записи: punch_host / punch_reflexive.
    types: [max_punch_candidates]u8,
    /// IPv4-октеты (сетевой порядок в памяти).
    ips: [max_punch_candidates][4]u8,
    /// Порты в host-порядке.
    ports: [max_punch_candidates]u16,
};

/// Максимум IPv6-адресов в V6_ADDR (все интерфейсы — редко больше двух:
/// временный + постоянный).
pub const max_v6_addrs: usize = 2;

/// V6_ADDR: фиксированный массив IPv6 + общий порт листенера
/// (безаллокационный decode).
pub const V6Addr = struct {
    /// Число заполненных записей (1..max_v6_addrs).
    count: u8,
    /// IPv6-байты (сетевой порядок в памяти).
    ips: [max_v6_addrs][16]u8,
    /// Порт листенера в host-порядке.
    port: u16,
};

/// Ошибки кодирования: мал буфер, payload превышает максимум протокола,
/// хвост entities не проходит валидацию либо поля кадра вне лимитов
/// (PUNCH count).
pub const EncodeError = codec.Writer.Error || error{ TooBig, BadEntities, BadLen };

/// Точная длина закодированного кадра `e` в байтах — для подбора буфера.
pub fn encodedLen(e: Envelope) usize {
    return switch (e) {
        .text => |m| 1 + id_len + 8 + 2 + m.body.len + tailLen(m.ents_tail),
        .reply_text => |m| 1 + id_len + 8 + id_len + 2 + m.body.len + tailLen(m.ents_tail),
        .react, .call_signal => 1 + id_len + 1,
        .block_notice => 2,
        .ack => 1 + id_len,
        .presence_ping, .presence_pong => 1 + 4 + 8,
        .call_audio => |m| 1 + 4 + 2 + m.data.len,
        .join => |m| 1 + 64 + 1 + m.name.len + join_sig_len + join_hmac_len,
        .profile => |m| 1 + 1 + m.name.len + id_len,
        .contact_card => |m| 1 + 1 + m.name.len + 64 + 2 + m.addr.len,
        .ratchet_key => 1 + 2 + 32,
        .sync => |m| 1 + 4 + 1 + m.recs.len,
        .sync_ack => 1 + 4,
        .punch => |m| 1 + 1 + @as(usize, m.count) * (1 + 4 + 2),
        .v6addr => |m| 1 + 1 + @as(usize, m.count) * 16 + 2,
        .avatar => |m| 1 + id_len + 2 + m.data.len,
        .file_meta => |m| 1 + id_len + 1 + m.name.len + 4 + 32,
        .file_data => |m| 1 + id_len + 4 + 2 + m.data.len,
        .file_ack => 1 + id_len + 4,
        .avatar_ack, .avatar_req => 1 + id_len,
    };
}

/// Длина хвоста entities на проводе: пустой срез — один байт счётчика 0.
fn tailLen(tail: []const u8) usize {
    return if (tail.len == 0) 1 else tail.len;
}

/// Кодирует `e` в `buf` и возвращает использованный срез `buf`.
/// Ошибки: NoSpace — буфер короче encodedLen(e); TooBig — тело TEXT > 4096
/// или DATA в CALL_AUDIO > 1024. Аллокаций нет.
/// Общая часть TEXT/REPLY_TEXT кодирования: тело + хвост entities
/// (после идентификаторов). Порядок байтов — контракт провода v3/v4.
fn putBodyAndTail(w: *codec.Writer, m: anytype) (codec.Writer.Error || error{BadEntities})!void {
    try w.putBytes(m.body);
    // хвост форматирования: пусто -> счётчик 0; иначе валидация
    // (границы/сортировка/правила value) и дословная запись
    if (m.ents_tail.len == 0) {
        try w.put(0);
    } else {
        _ = parseEntities(m.ents_tail, m.body.len, null) catch return error.BadEntities;
        try w.putFixed(m.ents_tail);
    }
}

pub fn encode(buf: []u8, e: Envelope) EncodeError![]const u8 {
    var w = codec.Writer.init(buf);
    switch (e) {
        .text => |m| {
            if (m.body.len > max_text_body) return error.TooBig;
            try w.put(@backingInt(Tag.text));
            try w.putFixed(&m.msg_id);
            try w.putInt(u64, m.ts_ms);
            try putBodyAndTail(&w, m);
        },
        .reply_text => |m| {
            if (m.body.len > max_text_body) return error.TooBig;
            try w.put(@backingInt(Tag.reply_text));
            try w.putFixed(&m.msg_id);
            try w.putInt(u64, m.ts_ms);
            try w.putFixed(&m.reply_to);
            try putBodyAndTail(&w, m);
        },
        .react => |m| {
            try w.put(@backingInt(Tag.react));
            try w.putFixed(&m.msg_id);
            try w.put(m.op);
            try w.putInt(u32, m.code);
        },
        .block_notice => |m| {
            try w.put(@backingInt(Tag.block_notice));
            try w.put(m.reason);
        },
        .ack => |m| {
            try w.put(@backingInt(Tag.ack));
            try w.putFixed(&m.msg_id);
        },
        .presence_ping => |m| {
            try w.put(@backingInt(Tag.presence_ping));
            try w.putInt(u32, m.seq);
            try w.putInt(u64, m.ts_ms);
        },
        .presence_pong => |m| {
            try w.put(@backingInt(Tag.presence_pong));
            try w.putInt(u32, m.seq);
            try w.putInt(u64, m.ts_peer_ms);
        },
        .call_signal => |m| {
            try w.put(@backingInt(Tag.call_signal));
            try w.put(m.op);
            try w.putFixed(&m.call_id);
        },
        .call_audio => |m| {
            if (m.data.len > max_audio_data) return error.TooBig;
            try w.put(@backingInt(Tag.call_audio));
            try w.putInt(u32, m.seq);
            try w.putBytes(m.data);
        },
        .join => |m| {
            if (m.name.len > max_join_name) return error.TooBig;
            try w.put(@backingInt(Tag.join));
            try w.putFixed(&m.bundle);
            try w.put(@intCast(m.name.len));
            try w.putFixed(m.name);
            try w.putFixed(&m.sig);
            try w.putFixed(&m.hmac);
        },
        .profile => |m| {
            if (m.name.len > max_join_name) return error.TooBig;
            try w.put(@backingInt(Tag.profile));
            try w.put(@intCast(m.name.len));
            try w.putFixed(m.name);
            try w.putFixed(&m.avatar_id);
        },
        .contact_card => |m| {
            if (m.name.len > max_card_name) return error.TooBig;
            if (m.addr.len > max_card_addr) return error.TooBig;
            try w.put(@backingInt(Tag.contact_card));
            try w.put(@intCast(m.name.len));
            try w.putFixed(m.name);
            try w.putFixed(&m.bundle);
            try w.putBytes(m.addr);
        },
        .ratchet_key => |m| {
            try w.put(@backingInt(Tag.ratchet_key));
            try w.putInt(u16, m.epoch);
            try w.putFixed(&m.dh_pub);
        },
        .sync => |m| {
            if (m.recs.len > max_sync_tail) return error.TooBig;
            if (m.count > max_sync_recs) return error.TooBig;
            // хвост обязан распарсиваться ровно на count записей: битый
            // хвост на провод не уходит
            _ = parseSyncRecs(m.recs, m.count, null) catch return error.TooBig;
            try w.put(@backingInt(Tag.sync));
            try w.putInt(u32, m.batch_id);
            try w.put(m.count);
            try w.putFixed(m.recs);
        },
        .sync_ack => |m| {
            try w.put(@backingInt(Tag.sync_ack));
            try w.putInt(u32, m.batch_id);
        },
        .punch => |m| {
            if (m.count == 0 or m.count > max_punch_candidates) return error.BadLen;
            try w.put(@backingInt(Tag.punch));
            try w.put(m.count);
            for (0..m.count) |i| {
                try w.put(m.types[i]);
                try w.putFixed(&m.ips[i]);
                try w.putInt(u16, m.ports[i]);
            }
        },
        .v6addr => |m| {
            if (m.count == 0 or m.count > max_v6_addrs) return error.BadLen;
            if (m.port == 0) return error.BadLen;
            try w.put(@backingInt(Tag.v6addr));
            try w.put(m.count);
            for (0..m.count) |i| {
                try w.putFixed(&m.ips[i]);
            }
            try w.putInt(u16, m.port);
        },
        .avatar => |m| {
            if (m.data.len > max_avatar_data) return error.TooBig;
            try w.put(@backingInt(Tag.avatar));
            try w.putFixed(&m.avatar_id);
            try w.putBytes(m.data);
        },
        .avatar_ack => |m| {
            try w.put(@backingInt(Tag.avatar_ack));
            try w.putFixed(&m.avatar_id);
        },
        .avatar_req => |m| {
            try w.put(@backingInt(Tag.avatar_req));
            try w.putFixed(&m.avatar_id);
        },
        .file_meta => |m| {
            if (m.name.len > max_file_name) return error.TooBig;
            try w.put(@backingInt(Tag.file_meta));
            try w.putFixed(&m.file_id);
            try w.put(@intCast(m.name.len));
            try w.putFixed(m.name);
            try w.putInt(u32, m.size);
            try w.putFixed(&m.sha);
        },
        .file_data => |m| {
            if (m.data.len > max_file_chunk) return error.TooBig;
            try w.put(@backingInt(Tag.file_data));
            try w.putFixed(&m.file_id);
            try w.putInt(u32, m.seq);
            try w.putBytes(m.data);
        },
        .file_ack => |m| {
            try w.put(@backingInt(Tag.file_ack));
            try w.putFixed(&m.file_id);
            try w.putInt(u32, m.got);
        },
    }
    return w.buf[0..w.pos];
}

/// Ошибки декодирования: кадр обрезан, тег неизвестен, есть лишний хвост
/// либо заявленная длина превышает максимум протокола.
pub const DecodeError = error{ Truncated, UnknownTag, BadLen };

/// Декодирует ровно один кадр из `bytes`. Срезы `body`/`data` указывают
/// в `bytes` (без копий). Хвост после кадра или превышение максимумов
/// протокола — BadLen. Аллокаций нет.
/// Общая часть декода TEXT/REPLY_TEXT: тело + хвост entities. Хвост —
/// остаток кадра: отсутствие байта счётчика (кадр v3) — Truncated, битые
/// записи — BadLen; валидный хвост потребляется целиком, хвоста после
/// него быть не может.
fn readBodyAndTail(r: *codec.Reader) DecodeError!struct { body: []const u8, tail: []const u8 } {
    const body = try r.getBytes();
    if (body.len > max_text_body) return error.BadLen;
    const tail = r.buf[r.pos..];
    _ = parseEntities(tail, body.len, null) catch |e| switch (e) {
        error.Truncated => return error.Truncated,
        else => return error.BadLen,
    };
    r.pos = r.buf.len;
    return .{ .body = body, .tail = tail };
}

pub fn decode(bytes: []const u8) DecodeError!Envelope {
    var r = codec.Reader.init(bytes);
    const tag_byte = try r.getU8();

    const e: Envelope = switch (tag_byte) {
        @backingInt(Tag.text) => blk: {
            const msg_id = try readId(&r);
            const ts_ms = try r.getInt(u64);
            const bt = try readBodyAndTail(&r);
            break :blk .{ .text = .{
                .msg_id = msg_id,
                .ts_ms = ts_ms,
                .body = bt.body,
                .ents_tail = bt.tail,
            } };
        },
        @backingInt(Tag.reply_text) => blk: {
            const msg_id = try readId(&r);
            const ts_ms = try r.getInt(u64);
            const reply_to = try readId(&r);
            const bt = try readBodyAndTail(&r);
            break :blk .{ .reply_text = .{
                .msg_id = msg_id,
                .ts_ms = ts_ms,
                .reply_to = reply_to,
                .body = bt.body,
                .ents_tail = bt.tail,
            } };
        },
        @backingInt(Tag.react) => .{ .react = .{
            .msg_id = try readId(&r),
            .op = try r.getU8(),
            .code = try r.getInt(u32),
        } },
        @backingInt(Tag.block_notice) => .{ .block_notice = .{
            .reason = try r.getU8(),
        } },
        @backingInt(Tag.presence_ping) => .{ .presence_ping = .{
            .seq = try r.getInt(u32),
            .ts_ms = try r.getInt(u64),
        } },
        @backingInt(Tag.presence_pong) => .{ .presence_pong = .{
            .seq = try r.getInt(u32),
            .ts_peer_ms = try r.getInt(u64),
        } },
        @backingInt(Tag.call_signal) => .{ .call_signal = .{
            .op = try r.getU8(),
            .call_id = try readId(&r),
        } },
        @backingInt(Tag.call_audio) => .{ .call_audio = .{
            .seq = try r.getInt(u32),
            .data = blk: {
                const data = try r.getBytes();
                if (data.len > max_audio_data) return error.BadLen;
                break :blk data;
            },
        } },
        @backingInt(Tag.ack) => .{ .ack = .{
            .msg_id = try readId(&r),
        } },
        @backingInt(Tag.join) => .{ .join = .{
            .bundle = (try r.getFixed(64))[0..64].*,
            .name = blk: {
                const nl = try r.getU8();
                if (nl == 0 or nl > max_join_name) return error.BadLen;
                break :blk try r.getFixed(nl);
            },
            .sig = (try r.getFixed(join_sig_len))[0..join_sig_len].*,
            .hmac = (try r.getFixed(join_hmac_len))[0..join_hmac_len].*,
        } },
        @backingInt(Tag.profile) => .{
            .profile = .{
                .name = blk: {
                    const nl = try r.getU8();
                    // 0 = имя не меняется (только avatar_id в этом PROFILE)
                    if (nl > max_join_name) return error.BadLen;
                    break :blk try r.getFixed(nl);
                },
                .avatar_id = (try r.getFixed(id_len))[0..id_len].*,
            },
        },
        @backingInt(Tag.contact_card) => .{ .contact_card = .{
            .name = blk: {
                const nl = try r.getU8();
                if (nl > max_card_name) return error.BadLen;
                break :blk try r.getFixed(nl);
            },
            .bundle = (try r.getFixed(64))[0..64].*,
            .addr = blk: {
                const addr = try r.getBytes();
                if (addr.len > max_card_addr) return error.BadLen;
                break :blk addr;
            },
        } },
        @backingInt(Tag.ratchet_key) => .{ .ratchet_key = .{
            .epoch = try r.getInt(u16),
            .dh_pub = (try r.getFixed(32))[0..32].*,
        } },
        @backingInt(Tag.sync) => blk: {
            const batch_id = try r.getInt(u32);
            const count = try r.getU8();
            if (count > max_sync_recs) return error.BadLen;
            const recs = r.buf[r.pos..];
            if (recs.len > max_sync_tail) return error.BadLen;
            // структура записей проверяется здесь; семантику (mac, kind)
            // проверяет приложение через parseSyncRecs
            _ = parseSyncRecs(recs, count, null) catch |e| switch (e) {
                error.Truncated => return error.Truncated,
                else => return error.BadLen,
            };
            r.pos = r.buf.len;
            break :blk .{ .sync = .{ .batch_id = batch_id, .count = count, .recs = recs } };
        },
        @backingInt(Tag.sync_ack) => .{ .sync_ack = .{
            .batch_id = try r.getInt(u32),
        } },
        @backingInt(Tag.punch) => blk: {
            var p: Punch = .{ .count = 0, .types = @splat(0), .ips = @splat(@splat(0)), .ports = @splat(0) };
            const count = try r.getU8();
            if (count == 0 or count > max_punch_candidates) return error.BadLen;
            p.count = count;
            for (0..count) |i| {
                const ty = try r.getU8();
                if (ty != punch_host and ty != punch_reflexive) return error.BadLen;
                p.types[i] = ty;
                p.ips[i] = (try r.getFixed(4))[0..4].*;
                p.ports[i] = try r.getInt(u16);
            }
            break :blk .{ .punch = p };
        },
        @backingInt(Tag.v6addr) => blk: {
            var v: V6Addr = .{ .count = 0, .ips = @splat(@splat(0)), .port = 0 };
            const count = try r.getU8();
            if (count == 0 or count > max_v6_addrs) return error.BadLen;
            v.count = count;
            for (0..count) |i| {
                v.ips[i] = (try r.getFixed(16))[0..16].*;
            }
            v.port = try r.getInt(u16);
            if (v.port == 0) return error.BadLen;
            break :blk .{ .v6addr = v };
        },
        @backingInt(Tag.avatar) => .{ .avatar = .{
            .avatar_id = (try r.getFixed(id_len))[0..id_len].*,
            .data = blk: {
                const data = try r.getBytes();
                if (data.len > max_avatar_data) return error.BadLen;
                break :blk data;
            },
        } },
        @backingInt(Tag.avatar_ack) => .{ .avatar_ack = .{
            .avatar_id = (try r.getFixed(id_len))[0..id_len].*,
        } },
        @backingInt(Tag.avatar_req) => .{ .avatar_req = .{
            .avatar_id = (try r.getFixed(id_len))[0..id_len].*,
        } },
        @backingInt(Tag.file_meta) => blk: {
            const file_id = try readId(&r);
            const name_len = try r.getU8();
            if (name_len > max_file_name) return error.BadLen;
            const name = try r.getFixed(name_len);
            const size = try r.getInt(u32);
            const sha = try r.getFixed(32);
            break :blk .{ .file_meta = .{
                .file_id = file_id,
                .name = name,
                .size = size,
                .sha = sha[0..32].*,
            } };
        },
        @backingInt(Tag.file_data) => blk: {
            const file_id = try readId(&r);
            const seq = try r.getInt(u32);
            const data = try r.getBytes();
            if (data.len > max_file_chunk) return error.BadLen;
            break :blk .{ .file_data = .{ .file_id = file_id, .seq = seq, .data = data } };
        },
        @backingInt(Tag.file_ack) => blk: {
            const file_id = try readId(&r);
            const got = try r.getInt(u32);
            break :blk .{ .file_ack = .{ .file_id = file_id, .got = got } };
        },
        else => return error.UnknownTag,
    };

    if (!r.done()) return error.BadLen;
    return e;
}

fn readId(r: *codec.Reader) DecodeError![id_len]u8 {
    var id: [id_len]u8 = undefined;
    @memcpy(&id, try r.getFixed(id_len));
    return id;
}
