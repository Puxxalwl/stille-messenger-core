//! Бинарный протокол ядрового API (UDS). Единственный контракт между
//! ядром stille-messenger и GUI-клиентом; полная спецификация — docs/CORE-API.md.
//!
//! Правила (как во всём проекте): little-endian через std.mem.readInt/
//! writeInt, никаких JSON и varint. Все кадры имеют одинаковый 16-байтный
//! заголовок, строки на проводе — счётчик длины + сырые байты (str16/str32).
//! Текста-человека на проводе нет: только типизированные байтовые структуры
//! и машинные коды статусов/методов/событий (SCREAMING_SNAKE в документации).

const std = @import("std");

/// Магия кадра: "ZP" (0x5A50) в первых двух байтах.
pub const magic: u16 = 0x5A50;
/// Версия протокола на проводе.
pub const version: u8 = 1;
/// Максимальная длина payload одного кадра (16 МиБ).
/// Лимит остаётся конечным: сервер выделяет буфер по длине кадра, поэтому
/// неограниченное значение превратило бы UDS в простой memory-DoS.
pub const max_payload: u32 = 16 * 1024 * 1024;
/// Длина заголовка любого кадра.
pub const header_len = 16;

/// Версия API (команда GET_VERSION): semver [major, minor, patch].
/// Major меняется на несовместимых изменениях провода.
/// 2.0.0: entities форматирования в SEND_MESSAGE/GET_HISTORY/GET_MESSAGE
/// и событии MESSAGE_RECEIVED (хвост после body, см. CORE-API.md).
/// 2.1.0: SEARCH_MESSAGE (23) и GLOBAL_SEARCH_MESSAGE (24) — поиск по
/// истории (регистронезависимый, точные + нечёткие совпадения).
/// 2.2.0: закрепления и удаление чатов, визитки; bit1 delivered в истории
/// теперь ставится только ACK-ом; GET_HISTORY/GET_MESSAGE/SEARCH читают
/// кэш истории в памяти.
/// 2.3.0: SEND_REPLY_MESSAGE и GET_REACTIONS.
/// 2.4.0: конфигурация ядра (GET_CONFIG/SET_CONFIG, событие
/// CONFIG_CHANGED) и прямой доступ клиента к БД (WRITE_DB/READ_DB/
/// DELETE_DB).
/// 2.5.0: GET_MY_AVATAR (40) — own avatar bytes, including after restart.
/// 2.6.0: восстановление доступа без истории — CREATE_RECOVERY_BACKUP (41),
/// RESTORE_RECOVERY_BACKUP (42) и статусы BAD_RECOVERY/NOT_INITIALIZED/
/// ALREADY_PROVISIONED; serve без сида поднимается в режиме восстановления.
/// 2.7.0 (релиз 0.3.0): наблюдаемое подключение и быстрые снимки —
/// GET_CONTACT_STATE (43), ACCEPT_INVITE_EX (44), SUBSCRIBE_CONTACT_UPDATES
/// (45), GET_BOOTSTRAP (46), GET_CONTACTS_DELTA (47), GET_REACHABLE_ENDPOINTS
/// (48), CREATE_INVITE_EX (49), GET_INVITE_STATE (50), GET_HISTORY_PAGE (51),
/// события CONTACT_STATE_CHANGED (15), CONTACTS_CHANGED (16),
/// CONTACT_UPSERTED (17) и статус RESYNC_REQUIRED (21). Все добавления
/// аддитивны: старые методы/события/форматы не менялись.
pub const api_version = [3]u16{ 2, 8, 0 };

/// Тип кадра.
pub const Kind = enum(u8) {
    /// Запрос клиента.
    request = 1,
    /// Ответ ядра на запрос (request_id echoed).
    response = 2,
    /// Событие ядра (рассылка всем клиентам).
    event = 3,
};

/// Методы API (u16 на проводе, имена SCREAMING_SNAKE — контракт).
pub const Method = enum(u16) {
    /// Закрыть соединение (не демон).
    CLOSE = 1,
    /// Версия API (проба готовности).
    GET_VERSION = 2,
    /// Свои публичные ключи: bundle + отпечаток.
    GET_IDENTITY = 3,
    /// Создать односторонний инвайт-код.
    CREATE_INVITE = 4,
    /// Погасить инвайт-код: добавить контакт (единственное действие держателя).
    ACCEPT_INVITE = 5,
    /// Список контактов.
    LIST_CONTACTS = 6,
    /// Отправить сообщение (контакт офлайн → очередь).
    SEND_MESSAGE = 7,
    /// Поставить реакцию на сообщение.
    SET_REACTION = 8,
    /// Снять реакцию со сообщения.
    REMOVE_REACTION = 9,
    /// История переписки с контактом.
    GET_HISTORY = 10,
    /// Одно сообщение (+ реакции) по msg_id.
    GET_MESSAGE = 11,
    /// Задать своё отображаемое имя.
    SET_NAME = 12,
    /// Задать свой аватар (байты inline).
    SET_AVATAR = 13,
    /// Текущий avatar_id контакта.
    GET_AVATAR_ID = 14,
    /// Передать файл контакту (путь в ФС пользователя ядра).
    SEND_FILE = 15,
    /// Инициировать звонок.
    START_CALL = 16,
    /// Принять входящий звонок.
    ANSWER_CALL = 17,
    /// Завершить/отклонить звонок.
    END_CALL = 18,
    /// Заблокировать контакт.
    BLOCK_CONTACT = 19,
    /// Разблокировать контакт.
    UNBLOCK_CONTACT = 20,
    /// Прямое подключение к контакту по адресу (обычно не нужно).
    CONNECT = 21,
    /// Слушать входящие подключения для контакта (обычно не нужно).
    LISTEN = 22,
    /// Поиск сообщений контакта по подстроке (без учёта регистра;
    /// точные и нечёткие совпадения, см. CORE-API.md).
    SEARCH_MESSAGE = 23,
    /// То же, но по всем чатам (записи ответа несут cid).
    GLOBAL_SEARCH_MESSAGE = 24,
    /// Закрепить чат (один закреплённый чат на ядро): [cid u32].
    PIN_CHAT = 25,
    /// Закреплённый чат: ответ [cid u32] (0 — не закреплено).
    GET_PINNED_CHAT = 26,
    /// Снять закрепление чата (идемпотентно).
    UNPIN_CHAT = 27,
    /// Удалить чат: контакт, история, очередь — всё. Ответ пуст.
    /// Повторное знакомство (новый инвайт) создаст чат заново с чистой историей.
    DELETE_CHAT = 28,
    /// Переслать контакту визитную карточку: [to_cid u32][contact_cid u32
    /// (0 = моя собственная)]. Получателю уходит событие CONTACT_CARD.
    SEND_CONTACT = 29,
    /// Закрепить сообщение в чате: [cid u32][msg_id 16] (≤ 16 на чат).
    PIN_MESSAGE = 30,
    /// Открепить сообщение: [cid u32][msg_id 16] (идемпотентно).
    UNPIN_MESSAGE = 31,
    /// Закреплённые сообщения чата: [cid u32] → [count u32] × {[msg_id 16]}
    /// в порядке закрепления.
    GET_PINNED_MESSAGES = 32,
    /// Ответить на сообщение: [cid][reply_to_msg_hex str16][body][entities].
    SEND_REPLY_MESSAGE = 33,
    /// Получить активные реакции: [msg_id 16] → максимум 3 записи.
    GET_REACTIONS = 34,
    /// Конфигурация ядра: ∅ → [ver u8][flags u32][server_addr str16]
    /// [tor_addr str16] (формат — app/config.zig).
    GET_CONFIG = 35,
    /// Записать конфигурацию: [ver u8][flags u32][server_addr str16]
    /// [tor_addr str16] → ∅. Проверяется семантика (server_mode требует
    /// адрес и т.п.); удачная запись рассылает CONFIG_CHANGED.
    SET_CONFIG = 36,
    /// Дописать клиентскую запись в шифрованную БД:
    /// [tag u8][data str32 ≤ 65000] → [rec_id u32][ts_ms u64].
    /// rec_id — номер записи лога (для DELETE_DB); при включённой
    /// device_sync запись реплицируется на связанные устройства.
    WRITE_DB = 37,
    /// Читать клиентские записи: [tag u8 (0xFF = все)][limit u32 (0 → 50,
    /// ≤ 200)][offset u32] → [total u32][count u32] × {[rec_id u32][ts_ms u64]
    /// [tag u8][data str16]} — старые → новые.
    READ_DB = 38,
    /// Удалить клиентскую запись: [rec_id u32] → ∅. Идемпотентно (tombstone
    /// лога); память освобождается при компакции.
    DELETE_DB = 39,
    /// Read own current avatar: ∅ → [avatar_id 16][data str16 1..16000].
    /// NOT_FOUND if unset or its bytes are unavailable; no ownership transfer.
    GET_MY_AVATAR = 40,
    /// Запечатать recovery-пакет: [unlock_secret 32] → [backup str32].
    /// Пакет = сид+профиль+контакты+блокировки+конфиг (БЕЗ истории),
    /// AEAD-запечатанный ключом из секрета GUI; блоб GUI хранит в
    /// пользовательском облаке. Требует провижненный профиль
    /// (NOT_INITIALIZED иначе); секрет ядро не сохраняет.
    CREATE_RECOVERY_BACKUP = 41,
    /// Восстановить профиль из пакета: [backup str32][unlock_secret 32]
    /// → [bundle 64][fingerprint 32][name str16]. Только пустой профиль
    /// (демон без сида): на живом — ALREADY_PROVISIONED; битый пакет или
    /// чужой секрет — BAD_RECOVERY. После успеха профиль провижен, сеть
    /// поднимается сама.
    RESTORE_RECOVERY_BACKUP = 42,
    /// Состояние подключения контакта: [cid u32] →
    /// [state u8][attempt u32][last_error u16][next_retry_ms u32].
    /// Snapshot-метод; события без опроса — SUBSCRIBE_CONTACT_UPDATES +
    /// CONTACT_STATE_CHANGED.
    GET_CONTACT_STATE = 43,
    /// Погасить инвайт-код (расширенный): payload как у ACCEPT_INVITE
    /// ([code str16][my_name str16]) →
    /// [cid u32][disposition u8][state u8][attempt u32].
    /// disposition: 0 accepted, 1 already_pending, 2 already_connected.
    /// Подключение НЕ блокирует ответ: dial уходит в планировщик.
    ACCEPT_INVITE_EX = 44,
    /// Подписаться на новые события контактов (CONTACT_STATE_CHANGED,
    /// CONTACTS_CHANGED, CONTACT_UPSERTED): ∅ → [epoch 16][revision u64].
    /// События до подписки не доставляются; подписка per-соединение.
    SUBSCRIBE_CONTACT_UPDATES = 45,
    /// Единый снимок для старта GUI: ∅ →
    /// [ver 3×u16][epoch 16][revision u64][count u32] × {contact_view}.
    /// contact_view: [cid u32][flags u8 bit0 online bit1 blocked
    /// bit2 pending][last_seen_ms i64][name str16][avatar_id 16]
    /// [state u8][attempt u32][last_error u16][next_retry_ms u32].
    GET_BOOTSTRAP = 46,
    /// Инкрементальная выгрузка изменений: [epoch 16][from_revision u64] →
    /// [epoch 16][to_revision u64][count u32] × {[revision u64][kind u8
    /// (0 upsert, 1 removed)][cid u32] + contact_view (только upsert)}.
    /// Чужая эпоха или ревизия выпала из кольца — RESYNC_REQUIRED;
    /// будущая ревизия — BAD_ARGS.
    GET_CONTACTS_DELTA = 47,
    /// Прямые LAN-адреса для QR: ∅ → [count u8] × [address str16]
    /// ("ip:port"). Пусто при выключенном листенере или use_tor_mask.
    GET_REACHABLE_ENDPOINTS = 48,
    /// Создать инвайт-код (расширенный): [mode u8][name str16 ≤ 32]
    /// [direct str16][relay str16] → [code str16][invite_id 16].
    /// mode: 0 discovery (адреса пусты, v2-код), 1 direct, 2 relay_only,
    /// 3 direct_then_relay (гибрид v3-код stille://i3/). invite_id —
    /// случайный НЕсекретный идентификатор для GET_INVITE_STATE.
    CREATE_INVITE_EX = 49,
    /// Состояние приглашения: [invite_id 16] →
    /// [state u8][accepted_cid u32][expires_at_ms i64 (0 = бессрочно)].
    /// state: 0 active, 1 joining, 2 consumed, 3 expired, 4 failed.
    /// joining означает, что валидный JOIN принят и идёт bind; consumed —
    /// bind завершён. CONTACT_JOINED выдаётся только после bind.
    GET_INVITE_STATE = 50,
    /// Страница истории (cursor-based): [cid u32][has_cursor u8]
    /// [before_ts u64][before_msg_id 16][limit u16 (0 → 30, ≤ 200)] →
    /// [has_more u8][next_ts u64][next_msg_id 16][count u32] × {запись
    /// GET_HISTORY}. has_cursor=0 — последние сообщения; курсор
    /// эксклюзивный, записи старые → новые, next_* = самое старое выданное
    /// (нули = конец истории).
    GET_HISTORY_PAGE = 51,
    /// Короткий код личности (диплинки stille.im/invite/{code}):
    /// [cid u32 (0 = я)] → [cid u32][code str16]. Код — 9 знаков,
    /// детерминированных из публичного bundle (без хранения), идентификатор
    /// без секретов: сам код не даёт прав и не раскрывает bundle.
    GENERATE_SHORT_CODE = 52,
    /// Локальный резолв короткого кода: [code str16] →
    /// [cid u32 (0 = я)][full_code str16] или NOT_FOUND. Код необратим
    /// (45 бит): резолвится только то, чей bundle известен локально —
    /// своя личность и сохранённые контакты. Для незнакомцев полный код
    /// берёт сайт-рендеву, ядро принимает его через ACCEPT_INVITE/EX.
    DECODE_SHORT_CODE = 53,
    /// Ротация персистентного кода профиля (эпоха в HKDF-выводе секрета):
    /// ∅ → [epoch u32][persisted u8]. Слитый код прошлой эпохи умирает
    /// немедленно; новый код — повторным CREATE_INVITE_EX mode 4.
    /// persisted=0 — лога нет (продолжение без хранения): эпоха живёт
    /// до рестарта. Существующие контакты и сессии не затрагиваются.
    REGENERATE_PROFILE_CODE = 54,
};

/// Коды статуса ответа (u16 на проводе, имена SCREAMING_SNAKE — контракт;
/// человекотекста в ответах нет).
pub const Status = enum(u16) {
    /// Успех.
    OK = 0,
    /// Кадр сломан: магия/версия/длина или payload не разобран.
    BAD_FRAME = 1,
    /// Неизвестный метод.
    UNKNOWN_METHOD = 2,
    /// Неверные/неполные аргументы метода.
    BAD_ARGS = 3,
    /// Контакт с таким cid не существует.
    NO_CONTACT = 4,
    /// Контакт заблокирован (локально).
    CONTACT_BLOCKED = 5,
    /// Объект не найден (сообщение по msg_id и т.п.).
    NOT_FOUND = 6,
    /// Превышен лимит размера (тело, аватар, кадр, история).
    TOO_BIG = 7,
    /// Инвайт-код не разобран/не распознан.
    BAD_INVITE_CODE = 8,
    /// Реестр приглашений полон.
    TOO_MANY_INVITES = 9,
    /// Файл по пути не найден/не читается.
    FILE_NOT_FOUND = 10,
    /// Недопустимая реакция: codepoint вне U+0000..U+10FFFF.
    UNSUPPORTED_REACTION = 11,
    /// Нет живой сессии с контактом (требуется для некоторых операций).
    NO_SESSION = 12,
    /// Линия занята (звонок уже идёт).
    BUSY = 13,
    /// Активного звонка нет.
    NO_CALL = 14,
    /// Релей недоступен.
    NO_RELAY = 15,
    /// Транспорт не поднялся (dial/рукопожатие).
    TRANSPORT_FAILED = 16,
    /// Tor SOCKS5-прокси недоступен (use_tor_mask включён).
    TOR_UNAVAILABLE = 17,
    /// Recovery-пакет непригоден: не разбирается, не расшифровывается
    /// (чужой секрет разблокировки) или неизвестная версия формата.
    BAD_RECOVERY = 18,
    /// Профиль не создан (демон в режиме восстановления без сида):
    /// личность ещё нет. GET_IDENTITY/CREATE_RECOVERY_BACKUP отказывают.
    NOT_INITIALIZED = 19,
    /// Профиль уже существует: RESTORE_RECOVERY_BACKUP требует пустой
    /// профиль (перезапись живого — отдельная явная операция сброса).
    ALREADY_PROVISIONED = 20,
    /// Delta-выгрузка невозможна: чужая эпоха демона или запрошенная
    /// ревизия выпала из кольца изменений. Клиент обязан сделать полный
    /// GET_BOOTSTRAP.
    RESYNC_REQUIRED = 21,
    /// Внутренняя ошибка ядра.
    INTERNAL = 255,
};

/// События ядра (u16 на проводе, имена SCREAMING_SNAKE — контракт).
pub const Event = enum(u16) {
    /// Входящее сообщение: [cid u32][msg_id 16][ts_ms u64][name str16]
    /// [body str16][ent_count u8] × {entity} (форматирование, CORE-API.md).
    MESSAGE_RECEIVED = 1,
    /// ACK: сообщение доставлено на устройство пира: [cid u32][msg_id 16].
    MESSAGE_DELIVERED = 2,
    /// Presence: [cid u32][online u8][last_seen_ms i64].
    PRESENCE = 3,
    /// Реакция от пира: [cid u32][msg_id 16][op u8][codepoint u32][ts_ms u64].
    REACTION = 4,
    /// Перемена состояния звонка: [cid u32][call_id 16][state u8 (CallState)].
    CALL_STATE = 5,
    /// Байты аватара пира: [cid u32][avatar_id 16][data str16].
    AVATAR_RECEIVED = 6,
    /// Файл принят целиком: [cid u32][file_id 16][size u32][name str16].
    FILE_RECEIVED = 7,
    /// Контакт погасил наш инвайт: [cid u32][name str16].
    CONTACT_JOINED = 8,
    /// Профиль контакта (имя/аватар) изменился: [cid u32][name str16][avatar_id 16].
    CONTACT_PROFILE = 9,
    /// Пир заблокировал нас: [cid u32].
    BLOCKED_BY_PEER = 10,
    /// Файл передан целиком (все чанки подтверждены FILE_ACK):
    /// [cid u32][file_id 16][size u32][name str16].
    FILE_SENT = 11,
    /// Пир переслал визитную карточку третьего лица (SEND_CONTACT у него):
    /// [cid u32 (кто прислал)][name str16][bundle 64][addr str16
    /// (пусто = неизвестен)].
    CONTACT_CARD = 12,
    /// Ответ на сообщение: [cid][msg_id][reply_to][ts][name][body][entities].
    REPLY_RECEIVED = 13,
    /// Конфигурация ядра изменилась (SET_CONFIG, в т.ч. применённая с
    /// другого устройства через device_sync): payload — новый blob
    /// [ver u8][flags u32][server_addr str16][tor_addr str16].
    CONFIG_CHANGED = 14,
    /// Стадия подключения контакта изменилась (только подписанным):
    /// [epoch 16][revision u64][cid u32][state u8][attempt u32]
    /// [last_error u16][next_retry_ms u32] — поля как GET_CONTACT_STATE.
    /// revision здесь — общая ревизия представления контактов.
    CONTACT_STATE_CHANGED = 15,
    /// Представление контактов изменилось (только подписанным):
    /// [epoch 16][revision u64]. Полный вид — CONTACT_UPSERTED или
    /// GET_CONTACTS_DELTA/GET_BOOTSTRAP.
    CONTACTS_CHANGED = 16,
    /// Полный контакт-view (только подписанным): [epoch 16][revision u64]
    /// [cid u32] + contact_view (поля как GET_BOOTSTRAP). Заменяет собой
    /// «дёрнуть LIST_CONTACTS» после CONTACT_JOINED/CONTACT_PROFILE.
    CONTACT_UPSERTED = 17,
};

/// Стадия установки соединения с контактом (u8 на проводе).
pub const ConnState = enum(u8) {
    /// Принят, ожидает первой попытки (контакт без адреса — ждёт LAN).
    pending = 0,
    /// Ждём анонса пира в LAN (мультикаст) — адреса нет.
    discovering = 1,
    /// TCP/relay dial идёт (блокирующая фаза транспорта).
    dialing = 2,
    /// Транспорт поднят, идёт рукопожатие (X25519+ML-KEM).
    handshaking = 3,
    /// JOIN отправлен, ждём PROFILE-эхо пира (подтверждение добавления).
    joining = 4,
    /// Сессия жива и аутентифицирована.
    online = 5,
    /// Живой сессии нет; автодозвон/пир поднимет её.
    offline = 6,
    /// Последняя попытка провалилась; см. last_error и next_retry_ms.
    failed = 7,
};

/// Код последней ошибки подключения (u16 на проводе; не строки — контракт).
pub const ConnErr = enum(u16) {
    none = 0,
    /// LAN-discovery выключен конфигурацией (lan_discovery = 0).
    discovery_disabled = 1,
    /// Транспорт недоступен (нет маршрута/интерфейса, dial отказал).
    transport_unavailable = 2,
    /// Транспорт не ответил за отведённое окно (таймаут dial/handshake).
    transport_timeout = 3,
    /// Аутентификация не прошла (рукопожатие/JOIN отвергнут). Детали не
    /// раскрываются намеренно (без oracle).
    auth_failed = 4,
    /// PROFILE-эхо после JOIN не пришло за окно наблюдения.
    join_timeout = 5,
    /// Планировщик подключений переполнен (очередь/активные слоты).
    capacity_exhausted = 6,
    /// Relay-маршрут недоступен (dial к релею отказал).
    relay_unreachable = 7,
    /// Tor SOCKS5-прокси недоступен (use_tor_mask включён).
    tor_unavailable = 8,
    /// Попытка отменена (блокировка/удаление чата/выключение).
    canceled = 9,
};

/// Расширенный ответ ACCEPT_INVITE_EX (u8 на проводе): информирует о
/// постановке работы, НЕ о доверии — контакт подтверждается только
/// аутентифицированным JOIN (см. PROTOCOL.md §6).
pub const AcceptDisposition = enum(u8) {
    /// Код погашен, контакт создан/найден, работа подключению поставлена.
    accepted = 0,
    /// Контакт уже есть и подключение уже в очереди/в полёте.
    already_pending = 1,
    /// С контактом уже живая сессия — новая работа не ставилась.
    already_connected = 2,
};

/// Режим CREATE_INVITE_EX (u8 на проводе).
pub const InviteExMode = enum(u8) {
    /// Адресов нет: v2-код без адреса, держатель ждёт LAN-анонс.
    discovery = 0,
    /// Прямой адрес: v2-код с @direct.
    direct = 1,
    /// Relay-адрес: v2-код с @r/relay (IP скрыт).
    relay_only = 2,
    /// Гибрид: v3-код stille://i3/ (direct, затем relay-fallback).
    direct_then_relay = 3,
    /// Персистентный код профиля: секрет не случайный, а выведен из
    /// сида (HKDF) — код НЕ сгорает после JOIN, реестр не занимается,
    /// лимита приглашений нет. Адреса: любые комбинации (для сайта/
    /// диплинков рекомендован relay — работает через сети). Повторный
    /// вызов с теми же аргументами даёт ТОТ ЖЕ код (детерминизм).
    profile = 4,
};

/// Состояние приглашения для GET_INVITE_STATE (u8 на проводе).
pub const InviteState = enum(u8) {
    /// Секрет жив, ждёт держателя кода.
    active = 0,
    /// Валидный JOIN получен, бинд идёт (короткое окно).
    joining = 1,
    /// Секрет погашен, контакт добавлен.
    consumed = 2,
    /// TTL кончился (в текущей модели не используется — коды живут до
    /// рестарта демона; значение зарезервировано).
    expired = 3,
    /// JOIN дошёл, но бинд/добавление провалились.
    failed = 4,
};

/// Тип изменения в GET_CONTACTS_DELTA (u8 на проводе).
pub const DeltaChange = enum(u8) {
    /// Запись/обновление контакта: за заголовком следует contact_view.
    upsert = 0,
    /// Чат удалён (tombstone): contact_view нет.
    removed = 1,
};

/// Состояние звонка для события CALL_STATE.
pub const CallState = enum(u8) {
    offer = 1,
    accept = 2,
    reject = 3,
    end = 4,
};

/// Заголовок кадра (одинаков для всех типов).
pub const Header = struct {
    kind: Kind,
    /// Метод (request/response) или событие (event).
    id: u16,
    /// Идентификатор запроса: клиент ставит, ядро повторяет в ответе.
    /// У событий всегда 0.
    request_id: u32,
    /// Статус (только response; у остальных OK).
    status: Status,
    payload_len: u32,
};

/// Записать заголовок кадра в out (16 байт, LE).
pub fn encodeHeader(out: *[header_len]u8, h: Header) void {
    std.mem.writeInt(u16, out[0..2], magic, .little);
    out[2] = version;
    out[3] = @backingInt(h.kind);
    std.mem.writeInt(u16, out[4..6], h.id, .little);
    std.mem.writeInt(u32, out[6..10], h.request_id, .little);
    std.mem.writeInt(u16, out[10..12], @backingInt(h.status), .little);
    std.mem.writeInt(u32, out[12..16], h.payload_len, .little);
}

/// Разобрать заголовок. null — неверная магия/версия.
pub fn decodeHeader(buf: *const [header_len]u8) ?Header {
    if (std.mem.readInt(u16, buf[0..2], .little) != magic) return null;
    if (buf[2] != version) return null;
    const kind = std.enums.fromInt(Kind, buf[3]) orelse return null;
    return .{
        .kind = kind,
        .id = std.mem.readInt(u16, buf[4..6], .little),
        .request_id = std.mem.readInt(u32, buf[6..10], .little),
        .status = std.enums.fromInt(Status, std.mem.readInt(u16, buf[10..12], .little)) orelse return null,
        .payload_len = std.mem.readInt(u32, buf[12..16], .little),
    };
}

/// Разбор payload запроса: курсор с проверкой границ.
/// Любое чтение за пределами — error.BadFrame.
pub const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(buf: []const u8) Reader {
        return .{ .buf = buf };
    }

    /// Остались ли непрочитанные байты.
    pub fn hasMore(self: *const Reader) bool {
        return self.pos < self.buf.len;
    }

    fn take(self: *Reader, n: usize) ![]const u8 {
        if (self.pos + n > self.buf.len) return error.BadFrame;
        const s = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return s;
    }

    pub fn readU8(self: *Reader) !u8 {
        return (try self.take(1))[0];
    }
    pub fn readU16(self: *Reader) !u16 {
        const b = try self.take(2);
        return std.mem.readInt(u16, b[0..2], .little);
    }
    pub fn readU32(self: *Reader) !u32 {
        const b = try self.take(4);
        return std.mem.readInt(u32, b[0..4], .little);
    }
    pub fn readU64(self: *Reader) !u64 {
        const b = try self.take(8);
        return std.mem.readInt(u64, b[0..8], .little);
    }
    pub fn readI64(self: *Reader) !i64 {
        const b = try self.take(8);
        return std.mem.readInt(i64, b[0..8], .little);
    }

    /// Фиксированный кусок байт (msg_id, bundle и т.п.).
    pub fn readBytes(self: *Reader, comptime n: usize) ![]const u8 {
        return self.take(n);
    }

    /// str8: [len u8][байты] — компактные значения (value entities).
    pub fn readStr8(self: *Reader) ![]const u8 {
        const len = try self.readU8();
        return self.take(len);
    }

    /// str16: [len u16][байты].
    pub fn readStr16(self: *Reader) ![]const u8 {
        const len = try self.readU16();
        return self.take(len);
    }

    /// str32: [len u32][байты].
    pub fn readStr32(self: *Reader) ![]const u8 {
        const len = try self.readU32();
        return self.take(len);
    }
};

/// Сборка payload ответа/события (аллокатор обязателен).
pub const Writer = struct {
    list: std.ArrayListUnmanaged(u8) = .empty,
    alloc: std.mem.Allocator,

    pub fn init(alloc: std.mem.Allocator) Writer {
        return .{ .alloc = alloc };
    }

    pub fn deinit(self: *Writer) void {
        self.list.deinit(self.alloc);
    }

    /// Готовые байты payload.
    pub fn items(self: *const Writer) []const u8 {
        return self.list.items;
    }

    pub fn putU8(self: *Writer, v: u8) !void {
        try self.list.append(self.alloc, v);
    }
    pub fn putU16(self: *Writer, v: u16) !void {
        var b: [2]u8 = undefined;
        std.mem.writeInt(u16, &b, v, .little);
        try self.list.appendSlice(self.alloc, &b);
    }
    pub fn putU32(self: *Writer, v: u32) !void {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, v, .little);
        try self.list.appendSlice(self.alloc, &b);
    }
    pub fn putU64(self: *Writer, v: u64) !void {
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, v, .little);
        try self.list.appendSlice(self.alloc, &b);
    }
    pub fn putI64(self: *Writer, v: i64) !void {
        var b: [8]u8 = undefined;
        std.mem.writeInt(i64, &b, v, .little);
        try self.list.appendSlice(self.alloc, &b);
    }
    pub fn putBytes(self: *Writer, v: []const u8) !void {
        try self.list.appendSlice(self.alloc, v);
    }
    /// str8: [len u8][байты] — компактные значения (value entities).
    pub fn putStr8(self: *Writer, v: []const u8) !void {
        if (v.len > std.math.maxInt(u8)) return error.BadArgs;
        try self.putU8(@intCast(v.len));
        try self.putBytes(v);
    }
    /// str16: [len u16][байты]; len > 65535 — error.BadArgs.
    pub fn putStr16(self: *Writer, v: []const u8) !void {
        if (v.len > std.math.maxInt(u16)) return error.BadArgs;
        try self.putU16(@intCast(v.len));
        try self.putBytes(v);
    }
    /// str32: [len u32][байты].
    pub fn putStr32(self: *Writer, v: []const u8) !void {
        try self.putU32(@intCast(v.len));
        try self.putBytes(v);
    }
};

test "header round-trip" {
    var buf: [header_len]u8 = undefined;
    encodeHeader(&buf, .{
        .kind = .response,
        .id = @backingInt(Method.SEND_MESSAGE),
        .request_id = 42,
        .status = .UNSUPPORTED_REACTION,
        .payload_len = 7,
    });
    const h = decodeHeader(&buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(Kind.response, h.kind);
    try std.testing.expectEqual(@as(u32, 42), h.request_id);
    try std.testing.expectEqual(Status.UNSUPPORTED_REACTION, h.status);
    try std.testing.expectEqual(@as(u32, 7), h.payload_len);
    try std.testing.expectEqual(@backingInt(Method.SEND_MESSAGE), h.id);
}

test "header rejects bad magic and version" {
    var buf: [header_len]u8 = undefined;
    @memset(&buf, 0);
    try std.testing.expect(decodeHeader(&buf) == null);
    encodeHeader(&buf, .{ .kind = .request, .id = 1, .request_id = 0, .status = .OK, .payload_len = 0 });
    buf[2] = 9;
    try std.testing.expect(decodeHeader(&buf) == null);
}

test "method ids стабильны (контракт провода)" {
    // SEARCH_MESSAGE/GLOBAL_SEARCH_MESSAGE — добавлены в 2.1.0; id
    // зафиксированы навсегда (как и остальные методы).
    try std.testing.expectEqual(@as(u16, 23), @backingInt(Method.SEARCH_MESSAGE));
    try std.testing.expectEqual(@as(u16, 24), @backingInt(Method.GLOBAL_SEARCH_MESSAGE));
    // закрепления/удаление/визитки — 2.2.0
    try std.testing.expectEqual(@as(u16, 25), @backingInt(Method.PIN_CHAT));
    try std.testing.expectEqual(@as(u16, 26), @backingInt(Method.GET_PINNED_CHAT));
    try std.testing.expectEqual(@as(u16, 27), @backingInt(Method.UNPIN_CHAT));
    try std.testing.expectEqual(@as(u16, 28), @backingInt(Method.DELETE_CHAT));
    try std.testing.expectEqual(@as(u16, 29), @backingInt(Method.SEND_CONTACT));
    try std.testing.expectEqual(@as(u16, 30), @backingInt(Method.PIN_MESSAGE));
    try std.testing.expectEqual(@as(u16, 31), @backingInt(Method.UNPIN_MESSAGE));
    try std.testing.expectEqual(@as(u16, 32), @backingInt(Method.GET_PINNED_MESSAGES));
    try std.testing.expectEqual(@as(u16, 33), @backingInt(Method.SEND_REPLY_MESSAGE));
    try std.testing.expectEqual(@as(u16, 34), @backingInt(Method.GET_REACTIONS));
    // конфигурация и клиентская БД — 2.4.0
    try std.testing.expectEqual(@as(u16, 35), @backingInt(Method.GET_CONFIG));
    try std.testing.expectEqual(@as(u16, 36), @backingInt(Method.SET_CONFIG));
    try std.testing.expectEqual(@as(u16, 37), @backingInt(Method.WRITE_DB));
    try std.testing.expectEqual(@as(u16, 38), @backingInt(Method.READ_DB));
    try std.testing.expectEqual(@as(u16, 39), @backingInt(Method.DELETE_DB));
    // восстановление доступа — 2.6.0
    try std.testing.expectEqual(@as(u16, 41), @backingInt(Method.CREATE_RECOVERY_BACKUP));
    try std.testing.expectEqual(@as(u16, 42), @backingInt(Method.RESTORE_RECOVERY_BACKUP));
    try std.testing.expectEqual(@as(u16, 18), @backingInt(Status.BAD_RECOVERY));
    try std.testing.expectEqual(@as(u16, 19), @backingInt(Status.NOT_INITIALIZED));
    try std.testing.expectEqual(@as(u16, 20), @backingInt(Status.ALREADY_PROVISIONED));
    // событие CONTACT_CARD — 2.2.0
    try std.testing.expectEqual(@as(u16, 12), @backingInt(Event.CONTACT_CARD));
    // событие CONFIG_CHANGED — 2.4.0
    try std.testing.expectEqual(@as(u16, 14), @backingInt(Event.CONFIG_CHANGED));
    // наблюдаемое подключение и снимки — 2.7.0 (релиз 0.3.0)
    try std.testing.expectEqual(@as(u16, 43), @backingInt(Method.GET_CONTACT_STATE));
    try std.testing.expectEqual(@as(u16, 44), @backingInt(Method.ACCEPT_INVITE_EX));
    try std.testing.expectEqual(@as(u16, 45), @backingInt(Method.SUBSCRIBE_CONTACT_UPDATES));
    try std.testing.expectEqual(@as(u16, 46), @backingInt(Method.GET_BOOTSTRAP));
    try std.testing.expectEqual(@as(u16, 47), @backingInt(Method.GET_CONTACTS_DELTA));
    try std.testing.expectEqual(@as(u16, 48), @backingInt(Method.GET_REACHABLE_ENDPOINTS));
    try std.testing.expectEqual(@as(u16, 49), @backingInt(Method.CREATE_INVITE_EX));
    try std.testing.expectEqual(@as(u16, 50), @backingInt(Method.GET_INVITE_STATE));
    try std.testing.expectEqual(@as(u16, 51), @backingInt(Method.GET_HISTORY_PAGE));
    // короткие коды личности — 2.8.0
    try std.testing.expectEqual(@as(u16, 52), @backingInt(Method.GENERATE_SHORT_CODE));
    try std.testing.expectEqual(@as(u16, 53), @backingInt(Method.DECODE_SHORT_CODE));
    try std.testing.expectEqual(@as(u16, 54), @backingInt(Method.REGENERATE_PROFILE_CODE));
    try std.testing.expectEqual(@as(u16, 15), @backingInt(Event.CONTACT_STATE_CHANGED));
    try std.testing.expectEqual(@as(u16, 16), @backingInt(Event.CONTACTS_CHANGED));
    try std.testing.expectEqual(@as(u16, 17), @backingInt(Event.CONTACT_UPSERTED));
    try std.testing.expectEqual(@as(u16, 21), @backingInt(Status.RESYNC_REQUIRED));
    // значения стадий подключения — контракт u8
    try std.testing.expectEqual(@as(u8, 0), @backingInt(ConnState.pending));
    try std.testing.expectEqual(@as(u8, 7), @backingInt(ConnState.failed));
    try std.testing.expectEqual(@as(u16, 0), @backingInt(ConnErr.none));
    try std.testing.expectEqual(@as(u16, 9), @backingInt(ConnErr.canceled));
    try std.testing.expectEqual(@as(u8, 0), @backingInt(AcceptDisposition.accepted));
    try std.testing.expectEqual(@as(u8, 2), @backingInt(AcceptDisposition.already_connected));
    try std.testing.expectEqual(@as(u8, 3), @backingInt(InviteExMode.direct_then_relay));
    try std.testing.expectEqual(@as(u8, 4), @backingInt(InviteExMode.profile));
    try std.testing.expectEqual(@as(u8, 4), @backingInt(InviteState.failed));
    try std.testing.expectEqual(@as(u8, 1), @backingInt(DeltaChange.removed));
    try std.testing.expectEqual(@as(u16, 2), api_version[0]);
    try std.testing.expectEqual(@as(u16, 8), api_version[1]);
}

test "reader/writer round-trip" {
    const alloc = std.testing.allocator;
    var w = Writer.init(alloc);
    defer w.deinit();
    try w.putU8(0xAB);
    try w.putU32(0xDEADBEEF);
    try w.putU64(0x1122334455667788);
    try w.putBytes(&@as([16]u8, @splat(7)));
    try w.putStr16("привет");
    try w.putStr32("bytes");

    var r = Reader.init(w.items());
    try std.testing.expectEqual(@as(u8, 0xAB), try r.readU8());
    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), try r.readU32());
    try std.testing.expectEqual(@as(u64, 0x1122334455667788), try r.readU64());
    try std.testing.expectEqualSlices(u8, &@as([16]u8, @splat(7)), try r.readBytes(16));
    try std.testing.expectEqualStrings("привет", try r.readStr16());
    try std.testing.expectEqualStrings("bytes", try r.readStr32());
    try std.testing.expect(!r.hasMore());

    // чтение за границей — BadFrame
    try std.testing.expectError(error.BadFrame, r.readU8());
    try std.testing.expectError(error.BadFrame, r.readStr16());
}
