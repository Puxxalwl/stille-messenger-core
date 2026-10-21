//! Состояние демона: App — единый владелец runtime-данных (контакты,
//! сессии, инвайты, sync, звонки, punch-маршруты, конфигурация).
//! Модуль НЕ содержит логики подсистем — только данные, типы, лимиты
//! и lock/unlock/nowMs. Подсистемы (events/connq/dial/receive/...)
//! импортируют app.zig; обратных зависимостей нет. Колбэки сессии
//! (session_bind/env_in/on_closed) — инверсия зависимости, как
//! tr_fn у sync: заполняются в main() до старта потоков.
const std = @import("std");
const stille_messenger = @import("stille-messenger");
const identity = stille_messenger.crypto.identity;
const engine_mod = stille_messenger.core.engine;
const session_mod = stille_messenger.core.session;
const envelope = stille_messenger.proto.envelope;
const hb = stille_messenger.net.heartbeat;
const obf = stille_messenger.net.obfuscate;
const tcp = stille_messenger.net.tcp;
const faketls_mod = stille_messenger.net.faketls;
const relay_mod = stille_messenger.net.relay;
const store_mod = stille_messenger.store.log;
const upnp_mod = stille_messenger.net.upnp;
const sysfd = stille_messenger.net.sysfd;
const config_mod = stille_messenger.app.config;
const sync_mod = stille_messenger.app.sync;
const wake = @import("wake.zig");
const audio_mod = @import("audio.zig");
const api_srv = @import("api_server.zig");
const invite_mod = @import("invite.zig");

// ------------------------------------------------------------------ call
/// Активный звонок: одна линия на процесс (v1), состояние под app.mu.
pub const CallState = struct {
    cid: i64,
    call_id: [16]u8,
    secret: [32]u8,
    start_ms: i64 = 0, // для таймера длительности
    seq: u32 = 0,
    /// Гудки/разговор. Установлено после accept.
    up: bool = false,
    pcm: ?audio_mod.PcmPort = null,
    audio_thread: ?std.Thread = null,
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    // ---- джиттер-буфер приёма (плейаут-очередь) ----
    jbuf: [16]JSlot = @splat(.{}),
    /// следующий seq к воспроизведению (инициализируется первым кадром).
    jplay_seq: u32 = 0,
    /// true — jplay_seq выставлен первым принятым кадром.
    jinit: bool = false,
    /// мс прихода первого кадра (для стартовой выдержки 60 мс).
    jfirst_ms: i64 = 0,
};

/// Слот джиттер-буфера: один декодированный кадр PCM.
pub const JSlot = struct {
    have: bool = false,
    pcm: [audio_mod.frame_bytes]u8 = @splat(0),
};

// ------------------------------------------------------------------ app
/// Роли линка устройства (контакт с bundle == нашим; контактная запись
/// лога хранит роль хвостовым байтом после relay-хвоста).
pub const dev_role_waiter: u8 = 1; // приглашающая сторона: не инициирует

pub const dev_role_holder: u8 = 2; // держатель кода линка: всегда инициирует

/// Клиентская запись БД (kind client, WRITE_DB) в кэше памяти.
pub const ClientRec = struct {
    /// Номер записи лога (rec_id для READ_DB/DELETE_DB).
    seq: u32,
    /// Пространство имён клиента (0..254; 0xFF — wildcard чтения).
    tag: u8,
    /// Метка времени записи (мс, ставит ядро).
    ts_ms: u64,
    /// Копия данных (owned).
    data: []u8,
};

/// Максимум данных одной клиентской записи (запись лога ≤ max_payload).
/// Wildcard-тег чтения клиентских записей (в WRITE_DB запрещён).
pub const client_tag_wildcard: u8 = 0xFF;

pub const max_client_data: usize = 65000;

/// Капа клиентской области БД (суммарно live-байтов кэша): WRITE_DB сверх
/// неё — TOO_BIG. Конечный бюджет памяти, как у всех очередей.
pub const client_db_cap: usize = 16 * 1024 * 1024;

pub const App = struct {
    alloc: std.mem.Allocator,
    io: std.Io,
    id: *identity.Identity,
    eng: *engine_mod.Engine,
    log: ?*store_mod.Log = null,
    hb: std.AutoHashMap(i64, hb.State),
    sess_ctx: std.AutoHashMap(i64, *SessCtx),
    raw_conns: std.ArrayListUnmanaged(*tcp.TcpConn) = .empty,
    obfs: std.ArrayListUnmanaged(*obf.ObfConn) = .empty,
    mu: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    call: ?*CallState = null,
    call_pcm_dir: ?[]const u8 = null,
    listen_port: u16 = 7777,
    // ---- UDS-апи (единственный интерфейс для GUI-клиента) ----
    cli: ?*api_srv.Server = null, // сервер (включён, когда != null)

    // ---- Односторонние инвайты (v2) ----
    /// Выданные приглашения: секрет ждёт предъявителя JOIN-конвертом.
    invites: [4]InviteReg = @splat(.{}),
    /// Число pending-сессий, ожидающих JOIN; ограничивает неизвестные входы.
    pending_sessions: u32 = 0,
    /// JOIN-данные по cid: отправить первым конвертом после рукопожатия.
    join_map: std.AutoHashMapUnmanaged(i64, JoinInfo) = .empty,
    /// Эпоха персистентного кода профиля (REGENERATE_PROFILE_CODE):
    /// входит в HKDF-вывод секрета. Ротация = bump + запись .set(8) в
    /// шифрованный лог; слитый код прошлой эпохи умирает немедленно
    /// (валидация JOIN принимает только текущую эпоху). Существующие
    /// контакты не зависят: их сессии живут по handshake, не по коду.
    profile_epoch: u32 = 0,
    /// Кэш аватаров: avatar_id -> байты (из лога kind AVATAR).
    avatars: std.AutoHashMapUnmanaged([16]u8, []u8) = .empty,
    /// Живые fake-TLS обёртки (для deinit по завершении).
    ftlss: std.ArrayListUnmanaged(*stille_messenger.net.faketls.FakeTlsConn) = .empty,
    /// Приём файлов в полёте: file_id -> RxFile.
    rx_files: std.AutoHashMapUnmanaged([16]u8, *RxFile) = .empty,
    /// Relay-адрес контакта (cid -> копия): держим присутствие в релее
    /// marker-ом из контакт-секрета, реконнект без нового инвайта.
    contact_relays: std.AutoHashMapUnmanaged(i64, []u8) = .empty,
    /// Запущенные presence-потоки (cid): защита от дублей.
    presence_runs: std.AutoHashMapUnmanaged(i64, void) = .empty,
    /// Кэш истории: сырые записи kind msg (owned, формат лога) —
    /// GET_HISTORY/GET_MESSAGE/SEARCH читают память, лог трогается только
    /// при записи. Заполняется при старте, пополняется в persistMsg.
    hist: std.ArrayListUnmanaged([]u8) = .empty,
    /// msg_id -> индекс в hist (одна запись на msg_id).
    hist_idx: std.AutoHashMapUnmanaged([16]u8, usize) = .empty,
    /// Закреплённый чат (cid; 0 — не закреплено). Переживает рестарт (set:3/set:4).
    pinned_chat: i64 = 0,
    /// Закреплённые сообщения: cid -> msg_id в порядке закрепления
    /// (переживает рестарт, set:5/set:6). Капа — max_pinned_msgs.
    pinned_msgs: std.AutoHashMapUnmanaged(i64, std.ArrayListUnmanaged([16]u8)) = .empty,
    /// Копия $HOME (для файлов/путей).
    home_buf: [512]u8 = @splat(0),
    home_len: usize = 0,

    // ---- Конфигурация и синхронизация устройств (2.4.0) ----
    /// Конфигурация ядра: GET_CONFIG/SET_CONFIG, kind cfg лога
    /// (последняя запись побеждает; пустой лог — defaults()).
    cfg: config_mod.Config = config_mod.Config.defaults(),
    /// Очереди синхронизации записей БД на устройства-линки (device_sync).
    /// init() в serve по сиду; поле обязательно инициализируется до
    /// loadContacts (линки регистрируются при загрузке).
    sync: sync_mod.Sync = undefined,
    /// Кэш клиентских записей БД (kind client): READ_DB читает память.
    client_recs: std.ArrayListUnmanaged(ClientRec) = .empty,
    /// MAC клиентских записей — дедуп повторной доставки синхронизации.
    client_macs: std.AutoHashMapUnmanaged([32]u8, void) = .empty,
    /// Суммарный размер клиентских записей (капа client_db_cap).
    client_bytes: usize = 0,
    /// Присутствие контактов на СВОЁМ сервере (server_mode): cid -> run.
    /// Отдельно от contact_relays (персональные релеи контактов).
    server_runs: std.AutoHashMapUnmanaged(i64, void) = .empty,

    // ---- NAT-punch (2.9.0) ----
    /// Рефлексивный адрес (каким relay видит подключение) по relay-конну:
    /// заполняется echo-dial-ами, читается один раз в bindSessionLocked
    /// при рассылке PUNCH_CANDIDATES. Ключ — указатель TcpConn: запись
    /// протухает с закрытием конна, карта ограничена relay_echo_cap
    /// (значения 8 байт, очистка безболезненна).
    relay_echo: std.AutoHashMapUnmanaged(*tcp.TcpConn, relay_mod.Reflexive) = .empty,
    /// Транспортный путь relay-сессии (cid): локальный адрес relay-конна
    /// + наши разосланные кандидаты + кандидаты пира (PUNCH_CANDIDATES).
    /// Снимается при бинде прямого пути (punched/LAN) и в onClosed.
    punch_routes: std.AutoHashMapUnmanaged(i64, PunchRoute) = .empty,
    /// Идущие punch-потоки (cid): дедуп запусков.
    punch_runs: std.AutoHashMapUnmanaged(i64, void) = .empty,
    /// UPnP-маппинг роутера (2.10.0): публичный IPv4-endpoint нашего
    /// листенера; null — роутер без UPnP или маппинг не удался.
    /// Guard: app.mu (записывает upnp-поток, читает всё остальное).
    upnp_ext: ?upnp_mod.Mapping = null,
    /// IPv6-листенер поднят ([::]:listen_port, V6ONLY — отдельный fd).
    listening6: bool = false,

    /// Тесты: подавить сетевые потоки из loadContacts (relay-присутствие,
    /// server-присутствие) — поток с dial'ами переживёт приложение из
    /// tmp-каталога. Продуктовый код флаг не устанавливает.
    no_network: bool = false,

    // ---- наблюдаемое подключение и снимки (2.7.0 / релиз 0.3.0) ----
    /// Очередь работ подключения и слоты активных попыток: connq_mu.
    connq_mu: std.Io.Mutex = .init,
    conn_work: std.ArrayListUnmanaged(ConnWork) = .empty,
    /// cid -> «в очереди или в полёте» (single-flight на контакт).
    conn_inflight: std.AutoHashMapUnmanaged(i64, void) = .empty,
    conn_active: u32 = 0,
    /// Состояния подключения (app.mu): GET_CONTACT_STATE/события.
    conn_st: std.AutoHashMapUnmanaged(i64, ConnEntry) = .empty,
    /// Ждём PROFILE-эхо после JOIN: cid -> монотонный дедлайн, нс (app.mu).
    conn_await: std.AutoHashMapUnmanaged(i64, i128) = .empty,
    /// Эпоха представления контактов: случайные НЕсекретные 16 байт,
    /// меняется на рестарте демона (клиент обязан resync).
    contacts_epoch: [16]u8 = @splat(0),
    /// Монотонная ревизия представления контактов (app.mu): растёт на
    /// каждом изменении contact_view (контакт/presence/state/avatar).
    contacts_rev: u64 = 0,
    /// Кольцо изменений для delta-выгрузки (app.mu): окно последних
    /// contact_ring_cap записей; пропавшая ревизия — RESYNC_REQUIRED.
    contacts_ring: [contact_ring_cap]ContactChange = @splat(.{}),
    contacts_ring_len: usize = 0,
    contacts_ring_pos: usize = 0,
    /// Завершённые приглашения (диагностика GET_INVITE_STATE, app.mu).
    invite_done: [invite_done_cap]InviteDone = @splat(.{}),
    invite_done_pos: usize = 0,
    invite_done_len: usize = 0,
    /// Слушатель автолистенера поднят (startNetworking): без него
    /// GET_REACHABLE_ENDPOINTS честно возвращает пустой список.
    listening: bool = false,
    /// Будилка цикла обнаружения (linkerLoop): событийные кики из
    /// потоков API (kickConnect) — анонс немедленно, без ожидания
    /// каденса. null — init не удался (цикл работает по каденсу).
    link_wake: ?wake.Waker = null,

    /// Профиль провижен: сид на диске, личность своя, лог открыт.
    /// false — режим восстановления (serve без сида): эфемерная личность,
    /// сети нет, RESTORE_RECOVERY_BACKUP доводит профиль до готовности
    /// (см. app/recovery.zig). Тесты по умолчанию провижнены.
    provisioned: bool = true,

    running: bool = true,

    /// Спин-блок: держится микросекунды (append в список), потоков мало.
    /// Инверсия зависимости (та же схема, что sync.tr_fn): слой
    /// установления соединений (dial.zig) привязывает сессии и получает
    /// их колбэки, не импортируя слой приёма (receive.zig). Заполняются
    /// в main() до старта потоков; после этого не меняются.
    session_bind: *const fn (app: *App, cid: i64, s: *session_mod.Session, sc: *SessCtx) error{OutOfMemory}!void,
    session_env_in: *const fn (ctx: *anyopaque, env: envelope.Envelope) void,
    session_on_closed: *const fn (ctx: *anyopaque) void,

    pub fn lock(self: *App) void {
        while (self.mu.swap(true, .acquire)) std.Thread.yield() catch {};
    }
    pub fn unlock(self: *App) void {
        self.mu.store(false, .release);
    }

    /// Время — прямой syscall: НЕ трогаем io, чтобы не конкурировать
    /// с сетевыми операциями из других потоков (Threaded io).
    pub fn nowMs(self: *App) i64 {
        _ = self;
        // sysfd: прямое чтение часов ОС без io (не конкурирует с сетью)
        return sysfd.wallMs();
    }
};

/// Relay-адрес приглашения/контакта (host:port, буфер).
pub const relay_addr_max = 64;

/// Выданное одностороннее приглашение (реестр в App.invites).
pub const InviteReg = struct {
    secret: [invite_mod.secret_len]u8 = @splat(0),
    created_ms: i64 = 0,
    /// true — код уже redeemed (секрет погашен).
    used: bool = false,
    /// Relay-адрес (если relay-инвайт): после JOIN — присутствие.
    relay_buf: [relay_addr_max]u8 = @splat(0),
    relay_len: u8 = 0,
    /// НЕсекретный случайный идентификатор приглашения (GET_INVITE_STATE,
    /// 2.7.0): по нему GUI опрашивает состояние; секрет по нему не
    /// восстанавливается и не логируется.
    invite_id: [16]u8 = @splat(0),
    /// JOIN в полёте (state JOINING до бинда): живое приглашение.
    joining: bool = false,
};

/// Завершённое приглашение (кольцо диагностики invite_done): consumed
/// или failed. Секрет не хранится — только идентификатор и результат.
pub const InviteDone = struct {
    invite_id: [16]u8 = @splat(0),
    /// api.InviteState (backing u8): consumed/failed.
    state: u8 = 0,
    /// cid добавленного контакта (0 при failed).
    accepted_cid: u32 = 0,
};

/// Капа завершённых приглашений для GET_INVITE_STATE: дальше — NOT_FOUND
/// (клиент обязан сам держать последний ответ, кольцо — только диагностика).
pub const invite_done_cap: usize = 64;

// ------------------------------------------------ подключение: планировщик
// Единая очередь подключений (2.7.0): ACCEPT_INVITE/ACCEPT_INVITE_EX/CONNECT
// больше не блокируют ответ на dial. Очередь и счётчик слотов — под
// connq_mu (НЕ под app.mu: сетевой I/O под спин-локом запрещён), состояния
// и метрики — под app.mu (там же fanout событий).

/// Капа очереди ожидающих подключений: больше — BUSY без побочных эффектов.
pub const conn_queue_cap: usize = 64;

/// Капа одновременных активных попыток подключения.
pub const conn_active_cap: u32 = 4;

/// Капа одновременно ожидающих неизвестных JOIN-сессий.
pub const pending_session_cap: u32 = 16;

/// Таймаут dial прямого адреса в гибрид-приглашении (i3), мс.
pub const direct_dial_timeout_ms: u32 = 3000;

/// Окно ожидания PROFILE-эха после JOIN (подтверждение добавления), мс.
pub const join_echo_timeout_ms: u64 = 5000;

/// Кольцо изменений представления контактов (GET_CONTACTS_DELTA).
pub const contact_ring_cap: usize = 4096;

/// Максимум контактов GET_BOOTSTRAP (как LIST_CONTACTS): больше — TOO_BIG.
pub const bootstrap_max_contacts: usize = 10000;

/// Одна работа подключения: адрес + признак релея + секрет marker-спаривания.
/// Секрет копия join_map — затирается secureZero по завершении работы.
pub const ConnWork = struct {
    cid: i64,
    addr_buf: [72]u8 = @splat(0),
    addr_len: u8 = 0,
    /// secret релей-приглашения (marker-спаривание; null — прямой dial).
    relay_secret: ?[16]u8 = null,
    /// Гибрид (i3): addr — ПРЯМОЙ адрес с таймаутом dial, relay_addr —
    /// fallback-релей (dial по relay_secret).
    hybrid: bool = false,
    relay_addr_buf: [72]u8 = @splat(0),
    relay_addr_len: u8 = 0,

    pub fn addr(self: *const ConnWork) []const u8 {
        return self.addr_buf[0..self.addr_len];
    }
    pub fn relayAddr(self: *const ConnWork) []const u8 {
        return self.relay_addr_buf[0..self.relay_addr_len];
    }
};

/// Состояние подключения контакта (app.mu): ответ GET_CONTACT_STATE и
/// источник события CONTACT_STATE_CHANGED.
pub const ConnEntry = struct {
    /// api.ConnState (backing u8).
    state: u8 = 0,
    /// Номер текущей/последней попытки (0 = попыток не было).
    attempt: u32 = 0,
    /// api.ConnErr (backing u16): код последней неудачи.
    last_error: u16 = 0,
    /// Абсолютные wall-мс следующего автодозвона (0 = повтор не назначен;
    /// в ответ/event отдаётся остаток до момента — насыщение до u32).
    next_retry_at: i64 = 0,
    /// Поколение попытки: инкремент на старте каждой; переходы от
    /// опоздавших callbacks с чужим поколением игнорируются.
    gen: u32 = 0,
};

/// Запись кольца изменений контактов (app.mu): revision 0 — пустой слот.
pub const ContactChange = struct {
    rev: u64 = 0,
    /// api.DeltaChange (backing u8).
    kind: u8 = 0,
    cid: u32 = 0,
};

/// JOIN-данные, которые отправим после установления сессии.
pub const JoinInfo = struct {
    secret: [invite_mod.secret_len]u8 = @splat(0),
    /// Моё имя — его увидит приглашающий.
    name_buf: [32]u8 = @splat(0),
    name_len: u8 = 0,

    pub fn name(self: *const JoinInfo) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

/// Контекст rx-потока сессии. Публичен как тип поля App.sess_ctx
/// (app/recovery.zig создаёт App в тестах).
pub const SessCtx = struct {
    app: *App,
    cid: i64,
    /// Сессия контекста: pending-join (cid == -1) — до промоушена,
    /// привязанная — выставляется в bindSessionLocked.
    s: ?*session_mod.Session = null,
    /// Учитывается в App.pending_sessions до успешного JOIN или закрытия.
    pending_counted: bool = false,
    /// Relay-конн, из которого поднята сессия (null — прямой путь:
    /// punched/LAN/autodial). В bindSessionLocked по нему берётся
    /// рефлексивный адрес и рассылаются PUNCH_CANDIDATES.
    relay_tc: ?*tcp.TcpConn = null,
    /// Конн пробит NAT-punch (simultaneous open): бинд рапортует
    /// ROUTE_STATE=direct_punched и снимает punch-маршрут.
    punched: bool = false,
    /// Прямой dial по host-кандидату пира (punch-воркер, инициатор):
    /// бинд рапортует ROUTE_STATE=lan.
    lan_dial: bool = false,
};

/// Тип прямого пути для establishSessionOnConn/handleAcceptedConn:
/// определяет маршрутизационные поля SessCtx (NAT-punch, 2.9.0).
pub const RouteKind = enum {
    /// Сессия поднимается на relay-конне: relay_tc заполняется, бинд
    /// разошлёт PUNCH_CANDIDATES и рапортует ROUTE_STATE=relay.
    relay,
    /// Пробитый NAT-punch конн (simultaneous open).
    punched,
    /// Прямой dial по host-кандидату (punch-воркер инициатора).
    lan_dial,
    /// Прочий прямой путь (TCP-accept листенера, autodial, discovery):
    /// punch не участвует, событий маршрута нет.
    direct,
};

/// Транспортный путь relay-сессии (NAT-punch, 2.9.0). Заполняется в
/// bindSessionLocked (наши адреса + факт рассылки), пополняется
/// кандидатами пира в envIn; punch-воркер читает снимком. Снятие —
/// бинд прямого пути либо onClosed relay-сессии.
pub const PunchRoute = struct {
    /// Локальный адрес relay-конна текущей сессии: punch-сокеты биндятся
    /// на него же (переиспользование NAT-маппинга, cone NAT).
    local_ip: [4]u8,
    local_port: u16,
    /// Наш рефлексивный кандидат (echo relay); port == 0 — relay без
    /// echo (старый): simultaneous open невозможен, только host-кандидаты.
    reflexive: relay_mod.Reflexive,
    /// Кандидаты пира (PUNCH_CANDIDATES из envIn).
    peer: envelope.Punch,
};

/// Лимит карты relay_echo (ключ — протухающие указатели коннов,
/// значения 8 байт): при заполнении карта очищается целиком.
pub const relay_echo_cap: usize = 64;

/// Пауза между циклами punch-воркера (мс): relay-сессия живёт, пробитие
/// не сложилось (symmetric NAT/фильтр) — повтор с умеренным ритмом.
pub const punch_retry_period_ms: u64 = 5000;

/// Таймаут host-dial из punch-воркера (мс): LAN-путь живой отвечает
/// быстро, дольше ждать бессмысленно (simultaneous open — следом).
pub const punch_host_dial_ms: u32 = 700;

/// Индекс контакта по указателю (события движка отдают *const Contact).
pub fn contactIndexOf(app: *App, from: *const engine_mod.Contact) ?usize {
    for (app.eng.contacts.items, 0..) |*it, i| {
        if (@intFromPtr(it) == @intFromPtr(from)) return i;
    }
    return null;
}

/// Найти cid по bundle (порядок стабильный: contacts[i] — id i+1).
/// Удалённые чаты невидимы: повторное знакомство с этим человеком создаст
/// НОВЫЙ cid с чистой историей.
pub fn contactIdByBundle(app: *App, bundle: [64]u8) ?i64 {
    for (app.eng.contacts.items, 0..) |c, i| {
        if (c.deleted) continue;
        if (std.mem.eql(u8, &c.bundle, &bundle)) return @intCast(i + 1);
    }
    return null;
}

/// Состояние приёма одного файла (FILE_META + чанки FILE_DATA).
pub const RxFile = struct {
    name_buf: [envelope.max_file_name]u8 = @splat(0),
    name_len: usize = 0,
    size: u32 = 0,
    sha: [32]u8 = @splat(0),
    expected_seq: u32 = 0,
    buf: std.ArrayListUnmanaged(u8) = .empty,

    pub fn name(self: *const RxFile) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

/// Капа закреплённых сообщений на чат.
pub const max_pinned_msgs = 16;
