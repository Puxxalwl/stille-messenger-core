//! stille-messenger: ядро шифрованного мессенджера. Только std, никаких JSON.
//! Интерфейс для клиентов — UDS-апи (cli_server.zig, см. docs/CORE-API.md).
//! Контакты, история и блокировки — в шифрованном логе (~/.stille-messenger/zig-log).
const std = @import("std");
const builtin = @import("builtin");
const stille_messenger = @import("stille-messenger");

const identity = stille_messenger.crypto.identity;
const engine_mod = stille_messenger.core.engine;
const session_mod = stille_messenger.core.session;
const envelope = stille_messenger.proto.envelope;
const hb = stille_messenger.net.heartbeat;
const obf = stille_messenger.net.obfuscate;
const tcp = stille_messenger.net.tcp;
const store_mod = stille_messenger.store.log;
const interfaces = stille_messenger.core.interfaces;
const invite_mod = @import("invite.zig");
const endpoints_mod = @import("endpoints.zig");
const discover_mod = @import("discover.zig");
const audio_mod = @import("audio.zig");
const adpcm_mod = @import("adpcm.zig");
const api_srv = @import("api_server.zig");
const api = @import("api.zig");
const recovery_mod = @import("recovery.zig");
const recovery_codec = stille_messenger.crypto.recovery;
const search_mod = @import("search.zig");
const config_mod = stille_messenger.app.config;
const sync_mod = stille_messenger.app.sync;
const socks5 = stille_messenger.net.socks5;
const sysfd = stille_messenger.net.sysfd;
const posix = std.posix;

const usage =
    \\stille-messenger-core — ядро шифрованного мессенджера (std-only Zig).
    \\Клиенты (GUI) подключаются через бинарное UDS-апи
    \\($HOME/.stille-messenger/api.sock). Спецификация — docs/CORE-API.md.
    \\
    \\  init    создать личность (~/.stille-messenger/zig-seed, 0600)
    \\  relay   режим IP-скрывающего релея (для сервера)
    \\  serve   демон: ядро + UDS-апи; без сида — режим восстановления
    \\
;
pub const app_home_max = 512;

/// Каталог данных: ~/.stille-messenger. Старый ~/.shopot мигрирует
/// атомарным rename при первом запуске новой версии.
pub const data_dir_name = ".stille-messenger";
pub const legacy_data_dir_name = ".shopot";

fn dataDirPath(out: []u8, home: []const u8, name: []const u8) ![]const u8 {
    return std.fmt.bufPrint(out, "{s}/{s}", .{ home, name });
}

fn directoryExists(io: std.Io, path: []const u8) !bool {
    std.Io.Dir.accessAbsolute(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}

/// Подготовить каталог данных. Новый уже есть — ничего не делаем; есть
/// только legacy — переносим атомарно; оба сразу — конфликт, запуск
/// запрещён (две установки молча не сливаются).
fn prepareDataDir(io: std.Io, home: []const u8) !void {
    if (home.len == 0) return error.NoHome;
    var current_buf: [app_home_max * 2]u8 = undefined;
    var legacy_buf: [app_home_max * 2]u8 = undefined;
    const current = try dataDirPath(&current_buf, home, data_dir_name);
    const legacy = try dataDirPath(&legacy_buf, home, legacy_data_dir_name);
    const has_current = try directoryExists(io, current);
    const has_legacy = try directoryExists(io, legacy);
    if (has_current and has_legacy) return error.DataMigrationConflict;
    if (has_current) return;
    if (has_legacy) {
        try std.Io.Dir.renamePreserve(.cwd(), legacy, .cwd(), current, io);
        return;
    }
    // 0700: каталог с сидом/логом/сокетом — только владелец
    try std.Io.Dir.createDirAbsolute(io, current, @fromBackingInt(@intCast(0o700)));
}

test "legacy data dir migrates atomically and conflicts are rejected" {
    const testing = std.testing;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmp.dir.realPathFileAlloc(io, ".", testing.allocator);
    defer testing.allocator.free(home);
    var legacy_buf: [app_home_max * 2]u8 = undefined;
    const legacy = try dataDirPath(&legacy_buf, home, legacy_data_dir_name);
    try std.Io.Dir.createDirAbsolute(io, legacy, @fromBackingInt(@as(u16, 0o700)));
    var legacy_seed_buf: [app_home_max * 2]u8 = undefined;
    const legacy_seed = try std.fmt.bufPrint(&legacy_seed_buf, "{s}/zig-seed", .{legacy});
    const seed_file = try std.Io.Dir.createFileAbsolute(io, legacy_seed, .{ .exclusive = true });
    defer seed_file.close(io);
    const seed_bytes: [32]u8 = @splat(0xA5);
    try seed_file.writePositionalAll(io, &seed_bytes, 0);
    try prepareDataDir(io, home);
    var current_buf: [app_home_max * 2]u8 = undefined;
    const current = try dataDirPath(&current_buf, home, data_dir_name);
    try testing.expect(try directoryExists(io, current));
    try testing.expect(!(try directoryExists(io, legacy)));
    try std.Io.Dir.createDirAbsolute(io, legacy, @fromBackingInt(@as(u16, 0o700)));
    try testing.expectError(error.DataMigrationConflict, prepareDataDir(io, home));
}

// тесты app-модулей, не импортируемых на уровне файла: zig build test
// (root main.zig) собирает тесты только явно процитированных файлов
test {
    _ = @import("recovery.zig");
    _ = @import("invite.zig");
    _ = @import("endpoints.zig");
}

/// $HOME копия App.home_buf.
pub fn appHomeDir(app: *const App) []const u8 {
    return app.home_buf[0..app.home_len];
}

fn stille_messengerDir(io: std.Io, home: []const u8) ![512]u8 {
    try prepareDataDir(io, home);
    var buf: [512]u8 = undefined;
    _ = try dataDirPath(&buf, home, data_dir_name);
    return buf;
}

/// Прочитать сид личности с диска (0600-файл). Используется стартом serve
/// и recovery-пакетом: в памяти ядра сид не удерживается.
pub fn loadSeed(io: std.Io, home: []const u8) ![32]u8 {
    _ = try stille_messengerDir(io, home);
    var path_buf: [512]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}/zig-seed", .{ home, data_dir_name });
    const f = try std.Io.Dir.openFileAbsolute(io, path, .{ .mode = .read_only });
    defer f.close(io);
    var seed: [32]u8 = undefined;
    const n = try f.readPositionalAll(io, &seed, 0);
    if (n != 32) return error.BadSeed;
    return seed;
}

/// Записать сид на диск (эксклюзивно, 0600): точка фиксации профиля.
pub fn saveSeed(io: std.Io, home: []const u8, seed: [32]u8) !void {
    _ = try stille_messengerDir(io, home);
    var path_buf: [512]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}/zig-seed", .{ home, data_dir_name });
    const f = try std.Io.Dir.createFileAbsolute(io, path, .{ .exclusive = true });
    defer f.close(io);
    try f.writePositionalAll(io, &seed, 0);
    f.setPermissions(io, .fromMode(0o600)) catch {};
}

pub fn toHex(out: []u8, bytes: []const u8) ![]u8 {
    var n: usize = 0;
    for (bytes) |b| {
        const p = try std.fmt.bufPrint(out[n..], "{x:0>2}", .{b});
        n += p.len;
    }
    return out[0..n];
}

fn parseMsgIdHex(text: []const u8) ?[16]u8 {
    if (text.len != 32) return null;
    var id: [16]u8 = undefined;
    _ = std.fmt.hexToBytes(&id, text) catch return null;
    return id;
}

// ------------------------------------------------------------------ call
/// Активный звонок: одна линия на процесс (v1), состояние под app.mu.
const CallState = struct {
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
const JSlot = struct {
    have: bool = false,
    pcm: [audio_mod.frame_bytes]u8 = @splat(0),
};

// ------------------------------------------------------------------ app
/// Роли линка устройства (контакт с bundle == нашим; контактная запись
/// лога хранит роль хвостовым байтом после relay-хвоста).
const dev_role_waiter: u8 = 1; // приглашающая сторона: не инициирует
const dev_role_holder: u8 = 2; // держатель кода линка: всегда инициирует

/// Клиентская запись БД (kind client, WRITE_DB) в кэше памяти.
const ClientRec = struct {
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

    /// Профиль провижен: сид на диске, личность своя, лог открыт.
    /// false — режим восстановления (serve без сида): эфемерная личность,
    /// сети нет, RESTORE_RECOVERY_BACKUP доводит профиль до готовности
    /// (см. app/recovery.zig). Тесты по умолчанию провижнены.
    provisioned: bool = true,

    running: bool = true,

    /// Спин-блок: держится микросекунды (append в список), потоков мало.
    pub fn lock(self: *App) void {
        while (self.mu.swap(true, .acquire)) std.Thread.yield() catch {};
    }
    pub fn unlock(self: *App) void {
        self.mu.store(false, .release);
    }

    /// Время — прямой syscall: НЕ трогаем io, чтобы не конкурировать
    /// с сетевыми операциями из других потоков (Threaded io).
    fn nowMs(self: *App) i64 {
        _ = self;
        // sysfd: прямое чтение часов ОС без io (не конкурирует с сетью)
        return sysfd.wallMs();
    }

    /// Привязать сессию к контакту. sc — контекст событий, уже создан и
    /// используется rx-потоком сессии, поэтому здесь не уничтожается никогда
    /// (короткоживущий процесс, счёт контекстов равен числу сессий).
    fn bindSession(self: *App, cid: i64, s: *session_mod.Session, sc: *SessCtx) !void {
        self.lock();
        defer self.unlock();
        return self.bindSessionLocked(cid, s, sc);
    }

    /// bind без взятия лока — вызывать ПОД self.mu.
    fn bindSessionLocked(self: *App, cid: i64, s: *session_mod.Session, sc: *SessCtx) !void {
        if (self.eng.sessions.get(cid)) |old| {
            // прошлую сессию — в retired: shutdown транспорта будит её
            // rx-поток, join и destroy сделает drainRetired тикера ВНЕ
            // лока (close+join здесь — deadlock: rx выходит через app.mu)
            self.eng.retireSession(cid, old);
        }
        try self.eng.sessions.put(cid, s);
        try self.sess_ctx.put(cid, sc);
        sc.s = s;
        // prime presence: считаем контакт живым сразу после рукопожатия
        const now = self.nowMs();
        self.eng.markSeen(cid, now);
        if (self.hb.getPtr(cid)) |st| st.onInbound(now);
        // сессия поднята — слить outbox (доставка офлайн-хвоста)
        self.eng.flushOutbox(cid);
        // ...и докачать файлы в полёте (с последнего подтверждённого чанка)
        self.eng.resumeFileTx(cid);
        // устройство-линк: слить очередь синхронизации записей БД
        syncFlushLocked(self, cid);
        // PROFILE-эхо: имя + avatar_id пир-у при каждом установлении
        self.eng.sendProfile(cid) catch {};
        // наблюдаемое состояние (2.7.0): сессия аутентифицирована; ждём
        // PROFILE-эхо после JOIN — JOINING (пир ещё не подтвердил добавление),
        // иначе ONLINE
        if (self.conn_await.contains(cid)) {
            connSetLocked(self, cid, .joining, .none, null);
        } else {
            connSetLocked(self, cid, .online, .none, null);
        }
        bumpContactLocked(self, cid);
    }

    fn events(self: *App) engine_mod.Events {
        return .{ .ctx = self, .onText = onTextEv, .onReply = onReplyEv, .onReaction = onReactionEv, .onPresence = onPresenceEv, .onProfile = onProfileEv, .onContactCard = onContactCardEv, .onBlockedNotice = onBlockedEv, .onCallSignal = onCallSignalEv, .onCallAudio = onCallAudioEv, .onDelivered = onDeliveredEv, .onAvatar = onAvatarEv, .onAvatarReq = onAvatarReqEv, .onFileMeta = onFileMetaEv, .onFileData = onFileDataEv, .onFileSent = onFileSentEv, .onSync = onSyncEv, .onSyncAck = onSyncAckEv };
    }
};

// ------------------------------------------------- события API (клиентам)
// Все evXxx собирают бинарный payload и рассылают его всем подключённым
// GUI-клиентам. ВЫЗЫВАТЬ ПОД app.mu: список conns живёт под этим локом.

/// MESSAGE_RECEIVED: входящее сообщение контакта. После body — хвост
/// entities форматирования ([ent_count u8] × {entity}, канонический формат
/// proto/envelope.zig); форматирования нет — один байт счётчика 0.
fn evMessageReceived(app: *App, cid: i64, msg_id: [16]u8, ts_ms: i64, name: []const u8, body: []const u8, ents: []const envelope.TextEntity) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putU32(@intCast(cid)) catch return;
    w.putBytes(&msg_id) catch return;
    w.putU64(@intCast(ts_ms)) catch return;
    w.putStr16(name) catch return;
    w.putStr16(body) catch return;
    putEntities(&w, body.len, ents) catch return;
    api_srv.fanoutEventLocked(app, .MESSAGE_RECEIVED, w.items());
}

fn evReplyReceived(app: *App, cid: i64, msg_id: [16]u8, reply_to: [16]u8, ts_ms: i64, name: []const u8, body: []const u8, ents: []const envelope.TextEntity) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putU32(@intCast(cid)) catch return;
    w.putBytes(&msg_id) catch return;
    w.putBytes(&reply_to) catch return;
    w.putU64(@intCast(ts_ms)) catch return;
    w.putStr16(name) catch return;
    w.putStr16(body) catch return;
    putEntities(&w, body.len, ents) catch return;
    api_srv.fanoutEventLocked(app, .REPLY_RECEIVED, w.items());
}

/// Хвост entities в payload ответа/события: те же канонические байты,
/// что на проводе TEXT и в логе. Ошибка валидации (не должно случаться —
/// движок уже валидировал) — счётчик 0.
fn putEntities(w: *api.Writer, body_len: usize, ents: []const envelope.TextEntity) !void {
    var tail_buf: [envelope.max_text_tail]u8 = undefined;
    const tail = envelope.encodeEntitiesTail(&tail_buf, ents, body_len) catch {
        try w.putU8(0);
        return;
    };
    try w.putBytes(tail);
}

/// MESSAGE_DELIVERED: ACK — сообщение дошло до устройства пира.
fn evMessageDelivered(app: *App, cid: i64, msg_id: [16]u8) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putU32(@intCast(cid)) catch return;
    w.putBytes(&msg_id) catch return;
    api_srv.fanoutEventLocked(app, .MESSAGE_DELIVERED, w.items());
}

/// PRESENCE: контакт на связи / пропал.
fn evPresence(app: *App, cid: i64, online: bool, last_seen_ms: i64) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putU32(@intCast(cid)) catch return;
    w.putU8(@intFromBool(online)) catch return;
    w.putI64(last_seen_ms) catch return;
    api_srv.fanoutEventLocked(app, .PRESENCE, w.items());
}

/// REACTION: реакция пира на сообщение (op: react_add/react_remove).
fn evReaction(app: *App, cid: i64, msg_id: [16]u8, op: u8, code: u32, ts_ms: i64) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putU32(@intCast(cid)) catch return;
    w.putBytes(&msg_id) catch return;
    w.putU8(op) catch return;
    w.putU32(code) catch return;
    w.putU64(@intCast(ts_ms)) catch return;
    api_srv.fanoutEventLocked(app, .REACTION, w.items());
}

/// CALL_STATE: перемена состояния звонка.
fn evCallState(app: *App, cid: i64, call_id: [16]u8, state: api.CallState) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putU32(@intCast(cid)) catch return;
    w.putBytes(&call_id) catch return;
    w.putU8(@backingInt(state)) catch return;
    api_srv.fanoutEventLocked(app, .CALL_STATE, w.items());
}

/// AVATAR_RECEIVED: байты аватара пира (клиент кэширует по avatar_id).
fn evAvatarReceived(app: *App, cid: i64, avatar_id: [16]u8, data: []const u8) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putU32(@intCast(cid)) catch return;
    w.putBytes(&avatar_id) catch return;
    w.putStr16(data) catch return;
    api_srv.fanoutEventLocked(app, .AVATAR_RECEIVED, w.items());
}

/// FILE_SENT: исходящий файл передан целиком — все чанки подтверждены
/// FILE_ACK-ами получателя.
fn evFileSent(app: *App, cid: i64, file_id: [16]u8, size: u32, name: []const u8) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putU32(@intCast(cid)) catch return;
    w.putBytes(&file_id) catch return;
    w.putU32(size) catch return;
    w.putStr16(name) catch return;
    api_srv.fanoutEventLocked(app, .FILE_SENT, w.items());
}

/// FILE_RECEIVED: файл принят целиком (байты в ~/.stille-messenger/files).
fn evFileReceived(app: *App, cid: i64, file_id: [16]u8, size: u32, name: []const u8) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putU32(@intCast(cid)) catch return;
    w.putBytes(&file_id) catch return;
    w.putU32(size) catch return;
    w.putStr16(name) catch return;
    api_srv.fanoutEventLocked(app, .FILE_RECEIVED, w.items());
}

/// CONTACT_JOINED: держатель кода погасил наш инвайт.
fn evContactJoined(app: *App, cid: i64, name: []const u8) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putU32(@intCast(cid)) catch return;
    w.putStr16(name) catch return;
    api_srv.fanoutEventLocked(app, .CONTACT_JOINED, w.items());
}

/// CONTACT_PROFILE: имя/avatar_id контакта обновились (эхо PROFILE).
fn evContactProfile(app: *App, cid: i64, name: []const u8, avatar_id: [16]u8) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putU32(@intCast(cid)) catch return;
    w.putStr16(name) catch return;
    w.putBytes(&avatar_id) catch return;
    api_srv.fanoutEventLocked(app, .CONTACT_PROFILE, w.items());
}

/// CONTACT_CARD: пир переслал визитку третьего лица.
fn evContactCard(app: *App, cid: i64, name: []const u8, bundle: [64]u8, addr: []const u8) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putU32(@intCast(cid)) catch return;
    w.putStr16(name) catch return;
    w.putBytes(&bundle) catch return;
    w.putStr16(addr) catch return;
    api_srv.fanoutEventLocked(app, .CONTACT_CARD, w.items());
}

/// BLOCKED_BY_PEER: пир заблокировал нас.
fn evBlockedByPeer(app: *App, cid: i64) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putU32(@intCast(cid)) catch return;
    api_srv.fanoutEventLocked(app, .BLOCKED_BY_PEER, w.items());
}

/// Relay-адрес приглашения/контакта (host:port, буфер).
const relay_addr_max = 64;

/// CONFIG_CHANGED: конфигурация изменилась (SET_CONFIG, в т.ч. применённая
/// с другого устройства). Payload — blob формата config.zig.
fn evConfigChanged(app: *App) void {
    var buf: [config_mod.blob_max]u8 = undefined;
    const blob = app.cfg.encode(&buf) catch return;
    api_srv.fanoutEventLocked(app, .CONFIG_CHANGED, blob);
}

// ----------------------------- наблюдаемое подключение (2.7.0 / 0.3.0)

/// CONTACT_STATE_CHANGED (только подписанным): [epoch 16][revision u64]
/// [cid u32][state u8][attempt u32][last_error u16][next_retry_ms u32].
/// ВЫЗЫВАТЬ ПОД app.mu.
fn evContactStateChangedLocked(app: *App, cid: i64) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putBytes(&app.contacts_epoch) catch return;
    w.putU64(app.contacts_rev) catch return;
    w.putU32(@intCast(cid)) catch return;
    const e = app.conn_st.get(cid) orelse ConnEntry{};
    w.putU8(e.state) catch return;
    w.putU32(e.attempt) catch return;
    w.putU16(e.last_error) catch return;
    w.putU32(retryRemainingMs(e.next_retry_at, app.nowMs())) catch return;
    api_srv.fanoutSubEventLocked(app, .CONTACT_STATE_CHANGED, w.items());
}

/// CONTACT_UPSERTED (только подписанным): [epoch 16][revision u64]
/// [cid u32] + contact_view. ВЫЗЫВАТЬ ПОД app.mu.
fn evContactUpsertedLocked(app: *App, cid: i64) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putBytes(&app.contacts_epoch) catch return;
    w.putU64(app.contacts_rev) catch return;
    w.putU32(@intCast(cid)) catch return;
    putContactViewLocked(app, &w, cid) catch return;
    api_srv.fanoutSubEventLocked(app, .CONTACT_UPSERTED, w.items());
}

/// CONTACTS_CHANGED (только подписанным): [epoch 16][revision u64] —
/// «представление изменилось, вытяни delta» (removal и объёмные случаи).
/// ВЫЗЫВАТЬ ПОД app.mu.
fn evContactsChangedLocked(app: *App) void {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    w.putBytes(&app.contacts_epoch) catch return;
    w.putU64(app.contacts_rev) catch return;
    api_srv.fanoutSubEventLocked(app, .CONTACTS_CHANGED, w.items());
}

/// Контакт ещё НЕ подтверждён пиром: JOIN не отправлен или PROFILE-эхо
/// после JOIN не получено. Имя такого контакта — локальная подсказка из
/// кода, НЕ аутентифицированный профиль. ВЫЗЫВАТЬ ПОД app.mu.
fn contactPendingLocked(app: *App, cid: i64) bool {
    return app.join_map.contains(cid) or app.conn_await.contains(cid);
}

/// Верхняя граница сериализованного contact_view (бюджет кадра:
/// 4+1+8+2+32+16+1+4+2+4 = 74 байта + str16-заголовок учтён).
const contact_view_size: usize = 4 + 1 + 8 + 2 + invite_mod.max_name + 16 + 1 + 4 + 2 + 4;

/// Эффективное состояние подключения контакта (view-семантика): запись
/// есть — её значение; нет — по факту сессии (online/offline).
/// ВЫЗЫВАТЬ ПОД app.mu.
fn connStateOfLocked(app: *App, cid: i64) api.ConnState {
    if (app.conn_st.get(cid)) |e| return @fromBackingInt(@intCast(e.state));
    const idx = app.eng.findIndex(cid) orelse return .offline;
    return if (app.eng.contacts.items[idx].online) .online else .offline;
}

/// Записать contact_view в сборщик ответа: [cid u32][flags u8 bit0 online
/// bit1 blocked bit2 pending][last_seen_ms i64][name str16][avatar_id 16]
/// [state u8][attempt u32][last_error u16][next_retry_ms u32].
/// ВЫЗЫВАТЬ ПОД app.mu.
fn putContactViewLocked(app: *App, w: *api.Writer, cid: i64) !void {
    const idx = app.eng.findIndex(cid) orelse return error.NoContact;
    const c = &app.eng.contacts.items[idx];
    var flags: u8 = 0;
    if (c.online) flags |= 1;
    if (c.blocked) flags |= 2;
    if (contactPendingLocked(app, cid)) flags |= 4;
    const seen: i64 = app.eng.lastSeen(cid) orelse 0;
    const e = app.conn_st.get(cid) orelse ConnEntry{};
    const state: api.ConnState = connStateOfLocked(app, cid);
    try w.putU32(@intCast(cid));
    try w.putU8(flags);
    try w.putI64(seen);
    try w.putStr16(c.getName());
    try w.putBytes(&c.avatar_id);
    try w.putU8(@backingInt(state));
    try w.putU32(e.attempt);
    try w.putU16(e.last_error);
    try w.putU32(retryRemainingMs(e.next_retry_at, app.nowMs()));
}

/// Добавить запись в кольцо изменений (app.mu): новая ревизия.
fn ringAppendLocked(app: *App, kind: api.DeltaChange, cid: i64) void {
    app.contacts_rev += 1;
    const slot = &app.contacts_ring[app.contacts_ring_pos];
    slot.* = .{ .rev = app.contacts_rev, .kind = @backingInt(kind), .cid = @intCast(cid) };
    app.contacts_ring_pos = (app.contacts_ring_pos + 1) % contact_ring_cap;
    if (app.contacts_ring_len < contact_ring_cap) app.contacts_ring_len += 1;
}

/// Представление контакта изменилось (профиль/presence/avatar/блокировка):
/// ревизия + кольцо + CONTACT_UPSERTED подписанным. ВЫЗЫВАТЬ ПОД app.mu.
fn bumpContactLocked(app: *App, cid: i64) void {
    ringAppendLocked(app, .upsert, cid);
    evContactUpsertedLocked(app, cid);
}

/// Чат удалён: ревизия + кольцо (removed) + CONTACTS_CHANGED. ВЫЗЫВАТЬ
/// ПОД app.mu.
fn bumpRemovedLocked(app: *App, cid: i64) void {
    ringAppendLocked(app, .removed, cid);
    evContactsChangedLocked(app);
}

/// Смена полей СОСТОЯНИЯ подключения: ревизия + кольцо (view включает
/// state) + CONTACT_STATE_CHANGED подписанным. gen — поколение попытки
/// работника (null — системные переходы: bind/close/profile). Переход
/// опоздавшего поколения молча игнорируется. ВЫЗЫВАТЬ ПОД app.mu.
fn connSetLocked(app: *App, cid: i64, state: api.ConnState, err: api.ConnErr, gen: ?u32) void {
    const gop = app.conn_st.getOrPut(app.alloc, cid) catch return;
    if (!gop.found_existing) gop.value_ptr.* = .{};
    if (gen) |g| {
        if (gop.found_existing and g != gop.value_ptr.gen) return;
        if (!gop.found_existing and g != 1) return;
    }
    const e = gop.value_ptr;
    if (e.state == @backingInt(state) and e.last_error == @backingInt(err)) return;
    e.state = @backingInt(state);
    e.last_error = @backingInt(err);
    if (e.next_retry_at != 0 and state != .failed) e.next_retry_at = 0;
    ringAppendLocked(app, .upsert, cid);
    evContactStateChangedLocked(app, cid);
}

/// Начало новой попытки подключения (dial): attempt += 1, gen += 1,
/// состояние dialing. Возвращает поколение для меток работника.
/// ВЫЗЫВАТЬ ПОД app.mu.
fn connBeginAttemptLocked(app: *App, cid: i64) u32 {
    const gop = app.conn_st.getOrPut(app.alloc, cid) catch return 0;
    gop.value_ptr.attempt += 1;
    gop.value_ptr.gen += 1;
    gop.value_ptr.state = @backingInt(api.ConnState.dialing);
    gop.value_ptr.last_error = @backingInt(api.ConnErr.none);
    gop.value_ptr.next_retry_at = 0;
    ringAppendLocked(app, .upsert, cid);
    evContactStateChangedLocked(app, cid);
    return gop.value_ptr.gen;
}

/// Контакт уходит в DISCOVERING (ждёт LAN-анонс пира; адреса нет).
/// ВЫЗЫВАТЬ ПОД app.mu.
fn connDiscoveringLocked(app: *App, cid: i64) void {
    connSetLocked(app, cid, .discovering, .none, null);
}

/// Осталось мс до повтора (насыщение до u32; 0 — повтора нет).
/// next_retry_at — абсолютные wall-мс (0 = не назначен).
fn retryRemainingMs(next_retry_at: i64, now: i64) u32 {
    if (next_retry_at <= 0 or next_retry_at <= now) return 0;
    const d: u64 = @intCast(next_retry_at - now);
    if (d > std.math.maxInt(u32)) return std.math.maxInt(u32);
    return @intCast(d);
}

/// Классификация ошибки установления соединения → ConnErr. Детали
/// отказа аутентификации НЕ раскрываются (без oracle-поведения).
fn connErrOf(e: anyerror) api.ConnErr {
    return switch (e) {
        error.Timeout => .transport_timeout,
        error.Network, error.BadAddress, error.Closed => .transport_unavailable,
        error.NoRelay => .relay_unreachable,
        error.NoTor => .tor_unavailable,
        error.OutOfMemory => .capacity_exhausted,
        else => .auth_failed,
    };
}

/// Ошибка ФАЗЫ dial (транспорт ещё не поднимался): гибрид-инвайт имеет
/// право упасть на relay-fallback. Отказ ПОСЛЕ dial (рукопожатие/JOIN) —
/// аутентификационный контекст, fallback запрещён.
fn isDialPhaseError(e: anyerror) bool {
    return switch (e) {
        error.Network, error.BadAddress, error.Timeout, error.NoRelay, error.NoTor, error.OutOfMemory => true,
        else => false,
    };
}

// ---------------------------------------------------- планировщик (connq)
// Инвариант порядка локов: connq_mu — листовой (НИКОГДА не берётся поверх
// app.mu из своих функций); app.mu → connq_mu вкладывать МОЖНО. Так
// enqueue решает «в полёте?» атомарно с решением по контакту.

/// Занят ли cid работой подключения (в очереди или в полёте).
fn connInflight(app: *App, cid: i64) bool {
    app.connq_mu.lockUncancelable(app.io);
    defer app.connq_mu.unlock(app.io);
    return app.conn_inflight.contains(cid);
}

/// Занять single-flight слот на контакт напрямую (autodial/linker/CONNECT,
/// работа БЕЗ очереди): занят — error.Busy (не дублируем dial).
fn connFlightBegin(app: *App, cid: i64) error{Busy}!void {
    app.connq_mu.lockUncancelable(app.io);
    defer app.connq_mu.unlock(app.io);
    if (app.conn_inflight.contains(cid)) return error.Busy;
    app.conn_inflight.put(app.alloc, cid, {}) catch return error.Busy;
}

/// Освободить прямой слот + прокачать очередь (мог освободиться активный).
fn connFlightEnd(app: *App, cid: i64) void {
    app.connq_mu.lockUncancelable(app.io);
    defer app.connq_mu.unlock(app.io);
    _ = app.conn_inflight.remove(cid);
    connPumpLocked(app);
}

/// Поставить работу подключения в очередь. error.Busy — уже в полёте или
/// очередь переполнена (cap conn_queue_cap: конечный бюджет, без unbounded).
fn connEnqueue(app: *App, work: ConnWork) error{Busy}!void {
    app.connq_mu.lockUncancelable(app.io);
    defer app.connq_mu.unlock(app.io);
    if (app.conn_inflight.contains(work.cid)) return error.Busy;
    if (app.conn_work.items.len >= conn_queue_cap) return error.Busy;
    app.conn_work.append(app.alloc, work) catch return error.Busy;
    app.conn_inflight.put(app.alloc, work.cid, {}) catch {
        _ = app.conn_work.pop();
        return error.Busy;
    };
    connPumpLocked(app);
}

/// Спавн работников на очередь, пока есть слоты (conn_active_cap).
/// ВЫЗЫВАТЬ ПОД connq_mu. Сетевого I/O здесь нет — только spawn.
fn connPumpLocked(app: *App) void {
    while (app.conn_active < conn_active_cap and app.conn_work.items.len > 0) {
        const work = app.conn_work.orderedRemove(0);
        app.conn_active += 1;
        const th = std.Thread.spawn(.{}, connWorker, .{ app, work }) catch {
            app.conn_active -= 1;
            // вернуть в голову; OOM на вставке — работа теряется (слот
            // и inflight сняты ниже), состояние остаётся по факту
            app.conn_work.insert(app.alloc, 0, work) catch {
                _ = app.conn_inflight.remove(work.cid);
            };
            break;
        };
        th.detach();
    }
}

/// Работник одной попытки подключения: dial → рукопожатие → JOIN — вся
/// сеть БЕЗ app.mu (спин-лок сетевой I/O держать нельзя). Финальный
/// провал — FAILED с классификацией; секрет релея затирается.
fn connWorker(app: *App, work: ConnWork) void {
    var w = work;
    defer {
        if (w.relay_secret) |*s| std.crypto.secureZero(u8, s);
        app.connq_mu.lockUncancelable(app.io);
        app.conn_active -= 1;
        _ = app.conn_inflight.remove(w.cid);
        connPumpLocked(app);
        app.connq_mu.unlock(app.io);
    }
    // стадия dialing + поколение; отмена (удалён/заблокирован) — выход
    var gen: u32 = 0;
    {
        app.lock();
        defer app.unlock();
        const idx = app.eng.findIndex(w.cid) orelse return;
        const c = &app.eng.contacts.items[idx];
        if (c.deleted) {
            connSetLocked(app, w.cid, .failed, .canceled, null);
            return;
        }
        if (c.blocked) {
            connSetLocked(app, w.cid, .failed, .canceled, null);
            return;
        }
        gen = connBeginAttemptLocked(app, w.cid);
    }
    var err: ?anyerror = null;
    if (w.hybrid and w.relay_secret != null) {
        // гибрид (i3): прямой адрес с таймаутом dial; отказ ТРАНСПОРТА
        // фазы dial — relay-fallback. Отказ после dial — без fallback.
        establishToRelay(app, w.addr(), .{ .cid = w.cid, .gen = gen, .dial_timeout_ms = direct_dial_timeout_ms }) catch |e| {
            if (isDialPhaseError(e)) {
                // fallback: marker-спаривание в релее (блокируется до пира)
                establishToRelay(app, w.relayAddr(), .{ .cid = w.cid, .gen = gen, .relay_secret = w.relay_secret }) catch |e2| {
                    err = e2;
                };
            } else {
                err = e;
            }
        };
    } else {
        establishToRelay(app, w.addr(), .{ .cid = w.cid, .gen = gen, .relay_secret = w.relay_secret }) catch |e| {
            err = e;
        };
    }
    // relay-маршрут: держать присутствие marker-ом (реконнекты без кода)
    if (w.relay_secret != null and !app.no_network) {
        app.lock();
        defer app.unlock();
        if (app.eng.findIndex(w.cid)) |idx| {
            if (!app.eng.contacts.items[idx].deleted and !app.eng.contacts.items[idx].blocked) {
                startRelayPresenceLocked(app, w.cid, w.relayAddr());
            }
        }
    }
    if (err) |e| {
        app.lock();
        defer app.unlock();
        connSetLocked(app, w.cid, .failed, connErrOf(e), gen);
    }
}

// --------------------------------------------- dial с дедлайном (неблокирующий)
// Linux — прямые syscall-ы std.os.linux (паттерн sysfd.zig), Darwin —
// libc-extern. После успеха fd возвращается в блокирующий режим: дальше
// сессия работает как после tcp.dial.

/// fcntl-константы (linux и darwin совпадают): F_GETFL=3, F_SETFL=4.
const fcntl_getfl: i32 = 3;
const fcntl_setfl: i32 = 4;
/// O_NONBLOCK: Linux 0o4000, Darwin 0x4.
const o_nonblock: usize = if (builtin.os.tag == .linux) 0o4000 else 0x4;

const dial_cabi = struct {
    extern "c" fn fcntl(fd: c_int, cmd: c_int, arg: c_int) c_int;
    extern "c" fn connect(fd: c_int, addr: *const posix.sockaddr, addrlen: posix.socklen_t) c_int;
    extern "c" fn getsockopt(fd: c_int, level: c_int, optname: c_int, optval: [*]u8, optlen: *posix.socklen_t) c_int;
};

/// Переключить неблокирующий режим fd. Ошибка — error.Network.
fn setNonblock(fd: posix.socket_t, on: bool) error{Network}!void {
    if (builtin.os.tag == .linux) {
        const fl = std.os.linux.fcntl(fd, fcntl_getfl, 0);
        if (std.os.linux.errno(fl) != .SUCCESS) return error.Network;
        const cur: usize = @intCast(fl);
        const want: usize = if (on) cur | o_nonblock else cur & ~o_nonblock;
        const rc = std.os.linux.fcntl(fd, fcntl_setfl, want);
        if (std.os.linux.errno(rc) != .SUCCESS) return error.Network;
        return;
    }
    const cur = dial_cabi.fcntl(@intCast(fd), fcntl_getfl, 0);
    if (cur < 0) return error.Network;
    const want: c_int = if (on) cur | @as(c_int, @intCast(o_nonblock)) else cur & ~@as(c_int, @intCast(o_nonblock));
    if (dial_cabi.fcntl(@intCast(fd), fcntl_setfl, want) < 0) return error.Network;
}

/// Прямой TCP dial с дедлайном (мс): connect в неблокирующем режиме +
/// poll. Таймаут — error.Timeout; отказ транспорта — error.Network;
/// некорректный адрес — error.BadAddress (классифицируется вызывающим).
/// Возвращает TcpConn с блокирующим fd (аллокатор приложения).
fn dialDeadline(app: *App, addr: []const u8, timeout_ms: u32) error{ Network, Timeout, BadAddress, OutOfMemory }!*tcp.TcpConn {
    const colon = std.mem.lastIndexOfScalar(u8, addr, ':') orelse return error.BadAddress;
    const host = addr[0..colon];
    const port = std.fmt.parseInt(u16, addr[colon + 1 ..], 10) catch return error.BadAddress;
    const ip4 = std.Io.net.Ip4Address.parse(host, port) catch return error.BadAddress;
    const sa = sysfd.sockaddrIn(ip4.bytes, port);
    const fd = sysfd.socketTcp() catch return error.Network;
    var failed = false;
    errdefer if (!failed) sysfd.close(fd);
    setNonblock(fd, true) catch {
        failed = true;
        return error.Network;
    };
    // connect: EINPROGRESS — норма для неблокирующего сокета
    if (builtin.os.tag == .linux) {
        const rc = std.os.linux.connect(fd, @ptrCast(&sa), @sizeOf(sysfd.SockaddrIn));
        const e = std.os.linux.errno(rc);
        if (e != .SUCCESS and e != .INPROGRESS) return error.Network;
    } else {
        const rc = dial_cabi.connect(@intCast(fd), @ptrCast(&sa), @sizeOf(sysfd.SockaddrIn));
        if (rc < 0 and posix.errno(rc) != .INPROGRESS) return error.Network;
    }
    var pfd = [1]posix.pollfd{.{ .fd = fd, .events = posix.POLL.OUT | posix.POLL.ERR | posix.POLL.HUP, .revents = 0 }};
    const n = posix.poll(&pfd, @intCast(timeout_ms)) catch return error.Network;
    if (n == 0) return error.Timeout;
    // итог connect: SO_ERROR (0 = успех)
    var so_err: i32 = 0;
    var so_len: posix.socklen_t = @sizeOf(i32);
    if (builtin.os.tag == .linux) {
        const rc = std.os.linux.getsockopt(fd, posix.SOL.SOCKET, posix.SO.ERROR, @ptrCast(&so_err), &so_len);
        if (std.os.linux.errno(rc) != .SUCCESS) return error.Network;
    } else {
        if (dial_cabi.getsockopt(@intCast(fd), posix.SOL.SOCKET, posix.SO.ERROR, @ptrCast(&so_err), &so_len) < 0) return error.Network;
    }
    if (so_err != 0) return error.Network;
    // назад в блокирующий режим — сессия читает как из tcp.dial
    setNonblock(fd, false) catch return error.Network;
    sysfd.setSocketBuffers(fd);
    sysfd.setQuickAck(fd);
    sysfd.setNoDelay(fd);
    const tc = app.alloc.create(tcp.TcpConn) catch return error.OutOfMemory;
    tc.* = .{ .fd = fd };
    sysfd.setKeepalive(fd);
    return tc;
}

// ------------------------------------------- синхронизация устройств (2.4.0)

/// Переводчик cid → bundle для очереди синхронизации (под app.mu).
/// Переводчик cid → bundle для SYNC (вызывается только под app.mu).
/// Публичен для app/recovery.zig (перепривязка после восстановления).
pub fn syncTranslateBundle(ctx: ?*anyopaque, cid: i64) ?[64]u8 {
    const app: *App = @ptrCast(@alignCast(ctx.?));
    if (cid < 1 or cid > app.eng.contacts.items.len) return null;
    return app.eng.contacts.items[@intCast(cid - 1)].bundle;
}

/// Постановка записи формата лога в очереди синхронизации всех устройств.
/// Вызывается ПОД app.mu из persist*/api* — сразу после записи в лог.
/// Записи больше sync_mod.max_rec (например, аватары 16 КБ) не синхронятся.
fn syncEnqueue(app: *App, kind: u8, payload: []const u8) void {
    if (!app.cfg.device_sync) return;
    app.sync.enqueue(kind, payload);
}

/// Слить очереди синхронизации всем устройствам с живыми сессиями.
/// Вызывается ПОД app.mu после постановки записей.
fn syncPumpLocked(app: *App) void {
    if (!app.cfg.device_sync) return;
    var it = app.sync.devices.keyIterator();
    while (it.next()) |cid| syncFlushLocked(app, cid.*);
}

/// Отдать очереди устройства по живой сессии партиями SYNC. Обрыв или
/// переполнение — партии возвращаются в очередь (повторная доставка
/// идемпотентна на приёме). Вызывается ПОД app.mu.
fn syncFlushLocked(app: *App, cid: i64) void {
    if (!app.cfg.device_sync) return;
    const s = app.eng.sessions.get(cid) orelse return;
    const d = app.sync.devices.get(cid) orelse return;
    var buf: [envelope.max_sync_tail]u8 = undefined;
    while (app.sync.takeBatch(d, &buf)) |b| {
        s.sendEnvelope(.{ .sync = .{
            .batch_id = b.batch_id,
            .count = b.count,
            .recs = b.tail,
        } }) catch {
            app.sync.onSessionDown(cid);
            return;
        };
    }
}

/// SYNC от устройства: проверить MAC каждой записи (ключ — только у
/// устройств с нашим сидом; подделка молча отбрасывается) и применить к
/// локальной БД; ответить SYNC_ACK. Работает в rx-потоке сессии под app.mu.
fn onSyncEv(ctx: *anyopaque, from: *const engine_mod.Contact, batch_id: u32, recs: []const u8, count: u8) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = contactIndexOf(app, from) orelse return;
    // неустройство прислать валидный SYNC не может (MAC), но и работы
    // на него не тратим
    if (!std.mem.eql(u8, &app.eng.contacts.items[idx].bundle, &app.id.bundle())) return;
    var views: [envelope.max_sync_recs]envelope.SyncRecView = undefined;
    const n = envelope.parseSyncRecs(recs, count, &views) catch 0;
    for (views[0..n]) |v| {
        if (!app.sync.verifyRec(v.kind, &v.mac, v.data)) continue;
        syncApplyRec(app, v.kind, &v.mac, v.data);
    }
    // партия обработана (применена или осознанно пропущена) — гасим
    if (app.eng.sessions.get(@intCast(idx + 1))) |s| {
        s.sendEnvelope(.{ .sync_ack = .{ .batch_id = batch_id } }) catch {};
    }
}

/// SYNC_ACK от устройства: партии подтверждены, очередь освобождается.
fn onSyncAckEv(ctx: *anyopaque, from: *const engine_mod.Contact, batch_id: u32) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = contactIndexOf(app, from) orelse return;
    app.sync.onAck(@intCast(idx + 1), batch_id);
}

/// Применить провалидированную MAC-ом запись SYNC к локальной БД.
/// Идемпотентно (дубликаты/повторы после обрыва ничего не меняют) и НЕ
/// ставит результат в исходящую очередь синхронизации (иначе петля
/// A→B→A). Вызывается ПОД app.mu.
fn syncApplyRec(app: *App, kind: u8, mac: *const [32]u8, data: []const u8) void {
    switch (kind) {
        @backingInt(sync_mod.RecKind.msg) => syncApplyMsg(app, data),
        @backingInt(sync_mod.RecKind.contact) => syncApplyContact(app, data),
        @backingInt(sync_mod.RecKind.block) => syncApplyBlock(app, data),
        @backingInt(sync_mod.RecKind.react) => syncApplyReact(app, data),
        @backingInt(sync_mod.RecKind.ack) => syncApplyAck(app, data),
        @backingInt(sync_mod.RecKind.file) => syncApplyFile(app, data),
        @backingInt(sync_mod.RecKind.client) => syncApplyClient(app, mac, data),
        @backingInt(sync_mod.RecKind.cfg) => syncApplyCfg(app, data),
        else => {},
    }
}

/// Запись msg: [bundle 64][flags][msg_id 16][ts 8][reply 16?][len 2][body][ents].
/// bundle → локальный cid; дубликат по msg_id пропускается. Чужие сообщения
/// поднимают событие клиенту, свои — только историю.
fn syncApplyMsg(app: *App, data: []const u8) void {
    if (data.len < 64 + 27) return;
    const cid = contactIdByBundle(app, data[0..64].*) orelse return;
    const rest = data[64..];
    const flags = rest[0];
    const msg_id = rest[1..17].*;
    if (app.hist_idx.contains(msg_id)) return;
    const has_reply = flags & 0b100 != 0;
    const body_off: usize = if (has_reply) 43 else 27; // координаты rest
    if (rest.len < body_off) return;
    const blen = std.mem.readInt(u16, rest[body_off - 2 ..][0..2], .little);
    if (blen > 4096) return;
    const body_end = body_off + blen;
    if (rest.len < body_end) return;
    const tail = rest[body_end..];
    _ = envelope.parseEntities(tail, blen, null) catch return;
    // пересборка записи с локальным cid
    var buf: [2 + 45 + 2 + 4096 + envelope.max_text_tail]u8 = undefined;
    std.mem.writeInt(u16, buf[0..2], @intCast(cid), .little);
    @memcpy(buf[2..][0..rest.len], rest);
    const rec = buf[0 .. 2 + rest.len];
    if (app.log) |log| _ = log.append(.msg, rec) catch {};
    histAppend(app, rec, msg_id);
    if (flags & 1 == 0) { // чужое сообщение — виден как входящее
        var ents: [envelope.max_text_entities]envelope.TextEntity = undefined;
        const n = envelope.parseEntities(tail, blen, &ents) catch 0;
        const c = &app.eng.contacts.items[@intCast(cid - 1)];
        const ts: i64 = @intCast(std.mem.readInt(u64, rest[17..25], .little));
        if (has_reply) {
            evReplyReceived(app, cid, msg_id, rest[27..43].*, ts, c.getName(), rest[body_off..body_end], ents[0..n]);
        } else {
            evMessageReceived(app, cid, msg_id, ts, c.getName(), rest[body_off..body_end], ents[0..n]);
        }
    }
}

/// Запись contact: формат лога (bundle-ключуемая). Неизвестный bundle —
/// добавляем контакт; свой bundle не создаём (линк — только явным кодом).
/// В локальный лог пишем только префикс [nlen][name][bundle]: хвосты
/// адресов/релея исходного устройства нам не нужны (свои адреса узнает
/// автодозвон/linker).
fn syncApplyContact(app: *App, data: []const u8) void {
    if (data.len < 66) return;
    const nlen: usize = data[0];
    if (data.len < 1 + nlen + 64) return;
    const bundle = data[1 + nlen ..][0..64].*;
    if (std.mem.eql(u8, &bundle, &app.id.bundle())) return;
    if (contactIdByBundle(app, bundle) != null) return; // уже знаем
    const idx = app.eng.addContact(data[1 .. 1 + nlen], bundle) catch return;
    app.hb.put(@intCast(idx + 1), .{}) catch {};
    if (app.log) |log| _ = log.append(.contact, data[0 .. 1 + nlen + 64]) catch {};
}

/// Запись block: [bundle 64][flag u8] — флаг контакта.
fn syncApplyBlock(app: *App, data: []const u8) void {
    if (data.len != 65) return;
    const cid = contactIdByBundle(app, data[0..64].*) orelse return;
    const c = &app.eng.contacts.items[@intCast(cid - 1)];
    if (c.deleted) return;
    c.blocked = data[64] != 0;
    if (app.log) |log| _ = log.append(.block, data) catch {};
    // v1: живую сессию не рвём — флаг применяется, notice/retire локально
}

/// Запись react: [bundle 64][flags][msg_id 16][op][code u32][ts u64];
/// пересборка с локальным cid, чужая реакция — событие клиенту.
fn syncApplyReact(app: *App, data: []const u8) void {
    if (data.len != 64 + 30) return;
    const cid = contactIdByBundle(app, data[0..64].*) orelse return;
    const rest = data[64..]; // [flags][msg_id 16][op][code][ts] = 30
    var buf: [32]u8 = undefined;
    std.mem.writeInt(u16, buf[0..2], @intCast(cid), .little);
    @memcpy(buf[2..][0..30], rest);
    if (app.log) |log| _ = log.append(.react, buf[0..32]) catch {};
    if (rest[0] == 0) { // чужая реакция
        const msg_id = rest[1..17].*;
        const op = rest[17];
        const code = std.mem.readInt(u32, rest[18..22], .little);
        const ts: i64 = @intCast(std.mem.readInt(u64, rest[22..30], .little));
        evReaction(app, cid, msg_id, op, code, ts);
    }
}

/// Запись ack: [msg_id 16] — глобальный идентификатор; локальный cid
/// берём из кэша истории, delivered гасится без повторной постановки
/// в очередь синхронизации.
fn syncApplyAck(app: *App, data: []const u8) void {
    if (data.len != 16) return;
    const msg_id = data[0..16].*;
    const i = app.hist_idx.get(msg_id) orelse return;
    const rec = app.hist.items[i];
    if (rec.len < 2) return;
    writeOutboxAck(app, @intCast(std.mem.readInt(u16, rec[0..2], .little)), msg_id);
}

/// Запись file: [bundle 64][file_id 16][size u32][nlen u8][name].
fn syncApplyFile(app: *App, data: []const u8) void {
    if (data.len < 64 + 23) return;
    const cid = contactIdByBundle(app, data[0..64].*) orelse return;
    const rest = data[64..];
    const nlen: usize = rest[22];
    if (rest.len != 23 + nlen) return;
    var buf: [23 + 64]u8 = undefined;
    std.mem.writeInt(u16, buf[0..2], @intCast(cid), .little);
    @memcpy(buf[2..][0..rest.len], rest);
    if (app.log) |log| _ = log.append(.file, buf[0 .. 23 + nlen]) catch {};
    evFileReceived(app, cid, rest[0..16].*, std.mem.readInt(u32, rest[16..20], .little), rest[23..]);
}

/// Запись client: [tag][ts 8][len 2][data]; дедуп по MAC, капа client_db_cap.
fn syncApplyClient(app: *App, mac: *const [32]u8, data: []const u8) void {
    if (data.len < 11) return;
    const dlen: usize = std.mem.readInt(u16, data[9..11], .little);
    if (dlen == 0 or dlen > max_client_data or data.len != 11 + dlen) return;
    if (app.client_macs.contains(mac.*)) return;
    if (app.client_bytes + dlen > client_db_cap) return;
    const seq = blk: {
        const log = app.log orelse return;
        break :blk log.append(.client, data) catch return;
    };
    clientCacheAppend(app, .{
        .seq = seq,
        .tag = data[0],
        .ts_ms = std.mem.readInt(u64, data[1..9], .little),
        .data = app.alloc.dupe(u8, data[11..]) catch return,
    }, mac.*);
}

/// Запись cfg: blob конфигурации. Применяется (валидация decode),
/// пишется в лог и рассылается CONFIG_CHANGED. Постановки в очередь
/// синхронизации НЕТ — применённое не ретранслируется (иначе петля).
fn syncApplyCfg(app: *App, data: []const u8) void {
    var c = app.cfg;
    c.decode(data) catch return;
    applyConfigLocked(app, c);
    if (app.log) |log| _ = log.append(.cfg, data) catch {};
    evConfigChanged(app);
}

/// Клиентские записи: WRAPPER кэша (память + MAC + счётчик).
fn clientCacheAppend(app: *App, rec: ClientRec, mac: [32]u8) void {
    app.client_recs.append(app.alloc, rec) catch {
        app.alloc.free(rec.data);
        return;
    };
    app.client_macs.put(app.alloc, mac, {}) catch {};
    app.client_bytes += rec.data.len;
}

/// Выданное одностороннее приглашение (реестр в App.invites).
const InviteReg = struct {
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

/// Запись в кольцо завершённых приглашений (GET_INVITE_STATE).
/// ВЫЗЫВАТЬ ПОД app.mu.
fn inviteDonePutLocked(app: *App, invite_id: [16]u8, state: api.InviteState, accepted_cid: u32) void {
    app.invite_done[app.invite_done_pos] = .{
        .invite_id = invite_id,
        .state = @backingInt(state),
        .accepted_cid = accepted_cid,
    };
    app.invite_done_pos = (app.invite_done_pos + 1) % invite_done_cap;
    if (app.invite_done_len < invite_done_cap) app.invite_done_len += 1;
    // приглашение больше не «в полёте»: used/joining расформированы
    for (&app.invites) |*reg| {
        if (reg.joining and std.mem.eql(u8, &reg.invite_id, &invite_id)) {
            reg.joining = false;
            std.crypto.secureZero(u8, &reg.secret);
        }
    }
}

/// Завершённое приглашение (кольцо диагностики invite_done): consumed
/// или failed. Секрет не хранится — только идентификатор и результат.
const InviteDone = struct {
    invite_id: [16]u8 = @splat(0),
    /// api.InviteState (backing u8): consumed/failed.
    state: u8 = 0,
    /// cid добавленного контакта (0 при failed).
    accepted_cid: u32 = 0,
};

/// Капа завершённых приглашений для GET_INVITE_STATE: дальше — NOT_FOUND
/// (клиент обязан сам держать последний ответ, кольцо — только диагностика).
const invite_done_cap: usize = 64;

// ------------------------------------------------ подключение: планировщик
// Единая очередь подключений (2.7.0): ACCEPT_INVITE/ACCEPT_INVITE_EX/CONNECT
// больше не блокируют ответ на dial. Очередь и счётчик слотов — под
// connq_mu (НЕ под app.mu: сетевой I/O под спин-локом запрещён), состояния
// и метрики — под app.mu (там же fanout событий).

/// Капа очереди ожидающих подключений: больше — BUSY без побочных эффектов.
const conn_queue_cap: usize = 64;
/// Капа одновременных активных попыток подключения.
const conn_active_cap: u32 = 4;
/// Капа одновременно ожидающих неизвестных JOIN-сессий.
const pending_session_cap: u32 = 16;
/// Таймаут dial прямого адреса в гибрид-приглашении (i3), мс.
const direct_dial_timeout_ms: u32 = 3000;
/// Окно ожидания PROFILE-эха после JOIN (подтверждение добавления), мс.
const join_echo_timeout_ms: u64 = 5000;
/// Кольцо изменений представления контактов (GET_CONTACTS_DELTA).
const contact_ring_cap: usize = 4096;
/// Максимум контактов GET_BOOTSTRAP (как LIST_CONTACTS): больше — TOO_BIG.
const bootstrap_max_contacts: usize = 10000;

/// Одна работа подключения: адрес + признак релея + секрет marker-спаривания.
/// Секрет копия join_map — затирается secureZero по завершении работы.
const ConnWork = struct {
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

    fn addr(self: *const ConnWork) []const u8 {
        return self.addr_buf[0..self.addr_len];
    }
    fn relayAddr(self: *const ConnWork) []const u8 {
        return self.relay_addr_buf[0..self.relay_addr_len];
    }
};

/// Состояние подключения контакта (app.mu): ответ GET_CONTACT_STATE и
/// источник события CONTACT_STATE_CHANGED.
const ConnEntry = struct {
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
const ContactChange = struct {
    rev: u64 = 0,
    /// api.DeltaChange (backing u8).
    kind: u8 = 0,
    cid: u32 = 0,
};

/// JOIN-данные, которые отправим после установления сессии.
const JoinInfo = struct {
    secret: [invite_mod.secret_len]u8 = @splat(0),
    /// Моё имя — его увидит приглашающий.
    name_buf: [32]u8 = @splat(0),
    name_len: u8 = 0,

    fn name(self: *const JoinInfo) []const u8 {
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
};

fn envIn(ctx: *anyopaque, env: envelope.Envelope) void {
    const sc: *SessCtx = @ptrCast(@alignCast(ctx));
    const app = sc.app;
    if (sc.cid == -1) {
        // pending-join: единственный допустимый конверт — JOIN
        handleJoinEnvelope(sc, env);
        return;
    }
    const now = app.nowMs();
    app.lock();
    defer app.unlock();
    app.eng.markSeen(sc.cid, now);
    if (app.hb.getPtr(sc.cid)) |st| {
        st.onInbound(now);
        switch (env) {
            .presence_pong => |pp| st.onPong(pp.seq, now),
            else => {},
        }
    }
    app.eng.dispatch(sc.cid, env);
}

/// JOIN на pending-сессии (sc.cid == -1): подпись привязывает bundle
/// заявителя к транскрипту (ключам сессии), HMAC доказывает держателя
/// инвайт-кода. Валидно — контакт добавляется, сессия биндится.
fn handleJoinEnvelope(sc: *SessCtx, env: envelope.Envelope) void {
    const app = sc.app;
    const sess = sc.s orelse return;
    // Мы В rx-потоке сессии: close() ждёт rx (join самого себя — deadlock),
    // поэтому гасим только транспорт — rx выйдет сам и рапортует onClosed.
    const j = switch (env) {
        .join => |j| j,
        else => {
            sess.shutdown();
            return;
        },
    };
    const transcript = sess.keys.transcript;
    // 1) подпись: bundle заявителя привязан к ключам этой сессии
    identity.Identity.verify(j.bundle[32..64].*, &transcript, j.sig) catch {
        sess.shutdown();
        return;
    };
    var failed = false;
    var cid: i64 = 0;
    var bind_failed = false;
    // invite_id для кольца диагностики (погашенного приглашения)
    var invite_done_id: [16]u8 = @splat(0);
    // relay-адрес приглашения: после JOIN — присутствие контакта
    var relay_addr_buf: [relay_addr_max]u8 = @splat(0);
    var relay_addr_len: usize = 0;
    {
        app.lock();
        defer app.unlock();
        if (sc.cid != -1) return; // уже промоутнут (повторный кадр)
        // 2) HMAC: секрет одного из живых (не погашенных) приглашений
        var matched: ?usize = null;
        for (&app.invites, 0..) |*reg, i| {
            if (reg.used) continue;
            var mac: [32]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, &transcript, &reg.secret);
            if (std.crypto.timing_safe.eql([32]u8, mac, j.hmac)) {
                matched = i;
                break;
            }
        }
        if (matched == null) {
            failed = true;
        } else {
            // корректный HMAC: приглашение расходуется, идём до бинда —
            // состояние JOINING (GET_INVITE_STATE). Секрет в реестре
            // больше не нужен: relay-linker владеет своей копией.
            app.invites[matched.?].used = true;
            app.invites[matched.?].joining = true;
            invite_done_id = app.invites[matched.?].invite_id;
            relay_addr_len = app.invites[matched.?].relay_len;
            @memcpy(relay_addr_buf[0..relay_addr_len], app.invites[matched.?].relay_buf[0..relay_addr_len]);
            // Relay-присутствие ещё использует секрет после JOIN; direct-код
            // можно стереть сразу. inviteDonePutLocked сотрёт relay-секрет.
            if (relay_addr_len == 0) std.crypto.secureZero(u8, &app.invites[matched.?].secret);
            if (contactIdByBundle(app, j.bundle)) |existing| {
                cid = existing; // переподключение держателем кода
            } else {
                const ni = app.eng.addContact(j.name, j.bundle) catch {
                    failed = true;
                    return;
                };
                cid = @intCast(ni + 1);
                app.hb.put(cid, .{}) catch {};
                // JOIN с нашим же bundle: линк устройства; приглашающая
                // сторона — «ждущая» (дозванивается всегда держатель кода)
                var role: u8 = 0;
                if (std.mem.eql(u8, &j.bundle, &app.id.bundle())) {
                    role = dev_role_waiter;
                    app.eng.contacts.items[ni].dev_role = role;
                    app.sync.addDevice(cid);
                }
                // контакт переживает рестарт: пишем в шифрованный лог
                if (app.log) |log| logContact(app, log, j.name, j.bundle, null, relay_addr_buf[0..relay_addr_len], role);
            }
            if (!failed) {
                sc.cid = cid;
                app.bindSessionLocked(cid, sess, sc) catch {
                    failed = true;
                    bind_failed = true;
                };
            }
        }
    }
    releasePendingLocked(sc);
    if (failed) {
        // bind не удался после корректного HMAC — приглашение FAILED
        // (секрет уже погашен: повторный JOIN тем же кодом невозможен)
        if (bind_failed) {
            app.lock();
            defer app.unlock();
            inviteDonePutLocked(app, invite_done_id, .failed, 0);
        }
        sess.shutdown();
        return;
    }
    // relay-инвайт: присутствие с этого момента — marker из
    // контакт-секрета, реконнекты без нового инвайта
    if (relay_addr_len > 0) {
        app.lock();
        defer app.unlock();
        startRelayPresenceLocked(app, cid, relay_addr_buf[0..relay_addr_len]);
    }
    app.lock();
    defer app.unlock();
    const name = app.eng.contacts.items[@intCast(cid - 1)].getName();
    evContactJoined(app, cid, name);
    evPresence(app, cid, true, app.nowMs());
    // приглашение погашено контактом: CONSUMED + представление — в ревизию
    inviteDonePutLocked(app, invite_done_id, .consumed, @intCast(cid));
    bumpContactLocked(app, cid);
}

/// Сессия умерла (её rx-поток завершился и рапортовал сюда). Снимаем
/// привязку с карты — ТОЛЬКО если она всё ещё наша (ребинд мог поставить
/// новую): иначе мёртвый указатель в eng.sessions навсегда блокирует
/// автодозвон и linker (обе петли видят «сессия есть» и не звонят), а
/// каждое sendText молча падает в outbox — «отправится позже» при живых
/// сторонах. Сессию уводим в retired: drain тикера сделает join+destroy.
fn onClosed(ctx: *anyopaque) void {
    const sc: *SessCtx = @ptrCast(@alignCast(ctx));
    if (sc.cid < 1) {
        // pending-сессия могла оборваться до JOIN и до таймера.
        releasePending(sc);
        return;
    }
    const s = sc.s orelse return;
    const app = sc.app;
    app.lock();
    defer app.unlock();
    const cur = app.eng.sessions.get(sc.cid) orelse return;
    if (cur != s) return; // уже заменена новой сессией — не трогаем
    app.eng.retireSession(sc.cid, s);
    _ = app.sess_ctx.remove(sc.cid);
    // неподтверждённые партии синхронизации — назад в очередь устройства
    app.sync.onSessionDown(sc.cid);
    if (app.eng.findIndex(sc.cid)) |idx| {
        app.eng.contacts.items[idx].online = false;
        if (app.eng.ev.onPresence) |cb|
            cb(app.eng.ev.ctx, &app.eng.contacts.items[idx], false, app.nowMs());
    }
    // наблюдаемое состояние (2.7.0): сессия потеряна — OFFLINE;
    // ожидание PROFILE-эха больше не имеет смысла
    _ = app.conn_await.remove(sc.cid);
    connSetLocked(app, sc.cid, .offline, .none, null);
    bumpContactLocked(app, sc.cid);
}

/// Индекс контакта по указателю (события движка отдают *const Contact).
fn contactIndexOf(app: *App, from: *const engine_mod.Contact) ?usize {
    for (app.eng.contacts.items, 0..) |*it, i| {
        if (@intFromPtr(it) == @intFromPtr(from)) return i;
    }
    return null;
}

fn onTextEv(ctx: *anyopaque, from: *const engine_mod.Contact, msg_id: [16]u8, _: i64, body: []const u8, ents: []const envelope.TextEntity) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = contactIndexOf(app, from) orelse return;
    const now = app.nowMs();
    persistMsg(app, @intCast(idx + 1), false, msg_id, null, true, now, body, ents);
    evMessageReceived(app, @intCast(idx + 1), msg_id, now, from.getName(), body, ents);
}

fn onReplyEv(ctx: *anyopaque, from: *const engine_mod.Contact, msg_id: [16]u8, _: i64, reply_to: [16]u8, body: []const u8, ents: []const envelope.TextEntity) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = contactIndexOf(app, from) orelse return;
    const now = app.nowMs();
    persistMsg(app, @intCast(idx + 1), false, msg_id, reply_to, true, now, body, ents);
    evReplyReceived(app, @intCast(idx + 1), msg_id, reply_to, now, from.getName(), body, ents);
}

/// Получен аватар: кэш (память + лог) + событие AVATAR_RECEIVED.
fn onAvatarEv(ctx: *anyopaque, from: *const engine_mod.Contact, avatar_id: [16]u8, data: []const u8) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = contactIndexOf(app, from) orelse return;
    // кэш: могли уже положить (дедуп по id)
    if (!app.avatars.contains(avatar_id)) {
        const copy = app.alloc.dupe(u8, data) catch return;
        app.avatars.put(app.alloc, avatar_id, copy) catch {
            app.alloc.free(copy);
            return;
        };
        if (app.log) |log| {
            var buf: [18 + 16000]u8 = undefined;
            @memcpy(buf[0..16], &avatar_id);
            std.mem.writeInt(u16, buf[16..18], @intCast(data.len), .little);
            @memcpy(buf[18 .. 18 + data.len], data);
            _ = log.append(.avatar, buf[0 .. 18 + data.len]) catch {};
        }
    }
    evAvatarReceived(app, @intCast(idx + 1), avatar_id, data);
    // avatar_id контакта изменился — представление для дельты/бутстрапа
    bumpContactLocked(app, @intCast(idx + 1));
}

/// FILE_META: начать приём файла (состояние под app.mu) и ответить
/// ПОЗИЦИОННЫМ FILE_ACK — отправитель докачивает с нашей позиции:
/// rx уже в полёте → expected_seq; файл сохранён ранее → total (готово);
/// свежий приём → 0.
fn onFileMetaEv(ctx: *anyopaque, from: *const engine_mod.Contact, meta: envelope.FileMeta) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const total: u32 = @intCast(@divTrunc(
        @as(u64, meta.size) + envelope.max_file_chunk - 1,
        envelope.max_file_chunk,
    ));
    var got: u32 = 0;
    if (app.rx_files.get(meta.file_id)) |rx| {
        got = rx.expected_seq; // докачка: пир продолжает с нашей позиции
    } else if (fileAlreadyStored(app, meta.file_id)) {
        got = total; // приняли ранее — отправителю можно завершать
    } else {
        const rx = app.alloc.create(RxFile) catch return;
        rx.* = .{ .size = meta.size, .sha = meta.sha };
        const n = @min(meta.name.len, envelope.max_file_name);
        @memcpy(rx.name_buf[0..n], meta.name[0..n]);
        rx.name_len = n;
        app.rx_files.put(app.alloc, meta.file_id, rx) catch {
            app.alloc.destroy(rx);
            return;
        };
    }
    const cid = contactIdByBundle(app, from.bundle) orelse return;
    app.eng.sendFileAck(cid, meta.file_id, got) catch {};
}

/// Период подтверждений приёмника (чанков между FILE_ACK) — окно
/// отправителя на той стороне (core/engine.zig, file_tx_window).
const rx_ack_every: u32 = 8;

/// Чанк FILE_DATA: копим; по последнему чанку — сверка SHA и сохранение.
/// ВЫЗЫВАЕТСЯ ПОД app.mu (из envIn).
fn onFileDataEv(ctx: *anyopaque, from: *const engine_mod.Contact, data: envelope.FileData) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const cid = contactIdByBundle(app, from.bundle) orelse return;
    const rx = app.rx_files.get(data.file_id) orelse return;
    if (data.seq != rx.expected_seq) return; // дубликат/дыра: ждём свой
    rx.expected_seq += 1;
    rx.buf.appendSlice(app.alloc, data.data) catch return;
    // периодический FILE_ACK: отправитель держит окно и позицию докачки
    if (rx.expected_seq % rx_ack_every == 0) {
        app.eng.sendFileAck(cid, data.file_id, rx.expected_seq) catch {};
    }
    if (rx.buf.items.len < rx.size) return;
    if (rx.buf.items.len != rx.size) { // перелив = поломка передачи
        dropRxFile(app, data.file_id);
        return;
    }
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(rx.buf.items, &digest, .{});
    if (!std.mem.eql(u8, &digest, &rx.sha)) { // битые байты
        dropRxFile(app, data.file_id);
        // сообщаем позицию 0: отправитель видит откат и шлёт заново
        app.eng.sendFileAck(cid, data.file_id, 0) catch {};
        return;
    }
    if (!saveRxFile(app, data.file_id, rx.buf.items)) {
        dropRxFile(app, data.file_id);
        return;
    }
    // лог kind FILE — перезапрос после рестарта не нужен
    persistFileMeta(app, @intCast(cid), data.file_id, rx.size, rx.name());
    evFileReceived(app, cid, data.file_id, rx.size, rx.name());
    // финальный ACK: все чанки подтверждены — отправитель закрывает передачу
    app.eng.sendFileAck(cid, data.file_id, rx.expected_seq) catch {};
    dropRxFile(app, data.file_id);
}

/// FILE_SENT от движка: исходящий файл передан целиком — все чанки
/// подтверждены FILE_ACK-ами получателя (состояние передачи ведёт движок,
/// app только рассылает событие GUI). ВЫЗЫВАЕТСЯ ПОД app.mu (из envIn).
fn onFileSentEv(ctx: *anyopaque, from: *const engine_mod.Contact, file_id: [16]u8, size: u32, name: []const u8) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const cid = contactIdByBundle(app, from.bundle) orelse return;
    evFileSent(app, cid, file_id, size, name);
}

fn dropRxFile(app: *App, file_id: [16]u8) void {
    const rx = app.rx_files.get(file_id) orelse return;
    _ = app.rx_files.remove(file_id);
    rx.buf.deinit(app.alloc);
    std.crypto.secureZero(u8, &rx.sha);
    app.alloc.destroy(rx);
}

/// Файл уже сохранён? (кэш ~/.stille-messenger/files/<id_hex32>)
fn fileAlreadyStored(app: *App, file_id: [16]u8) bool {
    var hxb: [32]u8 = undefined;
    const hx = toHex(&hxb, &file_id) catch return false;
    var fbuf: [700]u8 = undefined;
    const path = std.fmt.bufPrint(&fbuf, "{s}/{s}/files/{s}", .{ appHomeDir(app), data_dir_name, hx }) catch return false;
    var zbuf: [701]u8 = undefined;
    @memcpy(zbuf[0..path.len], path);
    zbuf[path.len] = 0;
    return sysfd.fileExists(@ptrCast(&zbuf));
}

/// Сохранить принятый файл (SHA уже сверена). true = записан.
fn saveRxFile(app: *App, file_id: [16]u8, bytes: []const u8) bool {
    var hxb: [32]u8 = undefined;
    const hx = toHex(&hxb, &file_id) catch return false;
    var pbuf: [600]u8 = undefined;
    const dir = std.fmt.bufPrint(&pbuf, "{s}/{s}/files", .{ appHomeDir(app), data_dir_name }) catch return false;
    var zbuf: [601]u8 = undefined;
    @memcpy(zbuf[0..dir.len], dir);
    zbuf[dir.len] = 0;
    sysfd.makeDir700(@ptrCast(&zbuf)); // EEXIST — не ошибка
    var fbuf: [700]u8 = undefined;
    const path = std.fmt.bufPrint(&fbuf, "{s}/{s}", .{ dir, hx }) catch return false;
    var zbuf2: [701]u8 = undefined;
    @memcpy(zbuf2[0..path.len], path);
    zbuf2[path.len] = 0;
    const fd = sysfd.createFile600(@ptrCast(&zbuf2)) orelse return false;
    defer sysfd.close(fd);
    sysfd.writeAll(fd, bytes) catch return false;
    return true;
}

/// Пир просит аватар с id: перекачать, если это наш текущий.
fn onAvatarReqEv(ctx: *anyopaque, from: *const engine_mod.Contact, avatar_id: [16]u8) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = contactIndexOf(app, from) orelse return;
    const cid: i64 = @intCast(idx + 1);
    // наш текущий аватар? (самоисцеление: profile сказал id, мы перекачали)
    if (!std.mem.eql(u8, &app.eng.my_avatar_id, &avatar_id)) return;
    const data = app.avatars.get(avatar_id) orelse return;
    _ = app.eng.sendAvatar(cid, data) catch {};
}

/// ACK дошёл: сообщение доставлено на устройство пир-а.
fn onDeliveredEv(ctx: *anyopaque, from: *const engine_mod.Contact, msg_id: [16]u8) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = contactIndexOf(app, from) orelse return;
    const cid: i64 = @intCast(idx + 1);
    persistOutboxAck(app, cid, msg_id);
    evMessageDelivered(app, cid, msg_id);
}

fn onReactionEv(ctx: *anyopaque, from: *const engine_mod.Contact, r: engine_mod.Reaction) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = contactIndexOf(app, from) orelse return;
    persistReact(app, @intCast(idx + 1), false, r.msg_id, r.op, r.code, app.nowMs());
    evReaction(app, @intCast(idx + 1), r.msg_id, r.op, r.code, app.nowMs());
}

fn onPresenceEv(ctx: *anyopaque, from: *const engine_mod.Contact, online: bool, last_seen_ms: i64) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = contactIndexOf(app, from) orelse return;
    const cid: i64 = @intCast(idx + 1);
    evPresence(app, cid, online, last_seen_ms);
    // наблюдаемое состояние (2.7.0): presence flip синхронизирует conn_st
    // (кроме JOINING — ждём PROFILE-эхо подтверждения добавления)
    if (!app.conn_await.contains(cid)) {
        connSetLocked(app, cid, if (online) .online else .offline, .none, null);
    }
    bumpContactLocked(app, cid);
}

fn onProfileEv(ctx: *anyopaque, from: *const engine_mod.Contact, name: []const u8, avatar_id: [16]u8) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = contactIndexOf(app, from) orelse return;
    const cid: i64 = @intCast(idx + 1);
    evContactProfile(app, cid, name, avatar_id);
    // PROFILE-эхо: пир жив и обработал наш JOIN (если ждали) — добавление
    // подтверждено. Эвристика, НЕ криптографическая квитанция.
    if (app.conn_await.remove(cid)) {
        connSetLocked(app, cid, .online, .none, null);
    }
    bumpContactLocked(app, cid);
}

/// CONTACT_CARD от пира: визитка третьего лица — наружу событием.
fn onContactCardEv(ctx: *anyopaque, from: *const engine_mod.Contact, name: []const u8, bundle: [64]u8, addr: []const u8) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = contactIndexOf(app, from) orelse return;
    evContactCard(app, @intCast(idx + 1), name, bundle, addr);
}

fn onBlockedEv(ctx: *anyopaque, from: *const engine_mod.Contact) void {
    const app: *App = @ptrCast(@alignCast(ctx));
    const idx = contactIndexOf(app, from) orelse return;
    evBlockedByPeer(app, @intCast(idx + 1));
}

// ------------------------------------------------------------- звонки
/// Входящий сигнал: offer — гудки, accept — линия вверх, reject/hangup — конец.
fn onCallSignalEv(ctx: *anyopaque, from: *const engine_mod.Contact, op: u8, call_id: [16]u8) void {
    // ВЫЗЫВАЕТСЯ ПОД app.mu (из envIn) — второго захвата быть не должно.
    const app: *App = @ptrCast(@alignCast(ctx));
    switch (op) {
        audio_mod.CallOp.offer => {
            if (app.call) |c| {
                // уже в звонке: отклоняем
                _ = app.eng.callSignal(c.cid, audio_mod.CallOp.reject, call_id) catch {};
                return;
            }
            const cid = contactIdByBundle(app, from.bundle) orelse return;
            const c = app.alloc.create(CallState) catch return;
            const zero_secret: [32]u8 = @splat(0);
            const secret = if (app.eng.sessions.get(cid)) |sess| sess.callSecret(call_id) else zero_secret;
            c.* = .{ .cid = cid, .call_id = call_id, .secret = secret };
            app.call = c;
            evCallState(app, cid, call_id, .offer);
        },
        audio_mod.CallOp.accept => {
            const c = app.call orelse return;
            if (!std.mem.eql(u8, &c.call_id, &call_id)) return;
            startCallAudio(app, c);
            evCallState(app, c.cid, call_id, .accept);
        },
        audio_mod.CallOp.reject => {
            const c = app.call orelse return;
            if (!std.mem.eql(u8, &c.call_id, &call_id)) return;
            evCallState(app, c.cid, call_id, .reject);
            endCallLocked(app, call_id);
        },
        audio_mod.CallOp.hangup => {
            const c = app.call orelse return;
            if (!std.mem.eql(u8, &c.call_id, &call_id)) return;
            endCallLocked(app, call_id);
        },
        else => {},
    }
}

/// Входящий аудиокадр: расшифровываем своим контуром и выводим в spk.
fn onCallAudioEv(ctx: *anyopaque, from: *const engine_mod.Contact, seq: u32, data: []const u8) void {
    // ВЫЗЫВАЕТСЯ ПОД app.mu (из envIn) — второго захвата быть не должно.
    const app: *App = @ptrCast(@alignCast(ctx));
    const c = app.call orelse return;
    if (!c.up) return;
    if (c.cid != contactIdByBundle(app, from.bundle) orelse return) return;
    // провод: [codec u8][AEAD-блок]; codec 1 = PCM, 2 = ADPCM
    if (data.len < 1 + aead_min) return;
    var plain: [audio_mod.frame_bytes]u8 = undefined; // вместимость для PCM
    const n = audio_mod.openFrame(&plain, c.secret, c.call_id, seq, data[1..]) catch return;
    var pcm_buf: [audio_mod.frame_bytes]u8 = undefined;
    var play: []const u8 = undefined;
    switch (data[0]) {
        audio_mod.codec_pcm => {
            if (n != audio_mod.frame_bytes) return;
            play = plain[0..n];
        },
        audio_mod.codec_adpcm => {
            if (n != audio_mod.adpcm_block) return;
            const got = adpcm_mod.decodeBlock(&pcm_buf, plain[0..n]);
            if (got != audio_mod.frame_bytes) return;
            play = pcm_buf[0..got];
        },
        else => return, // неизвестный кодек: кадр отброшен
    }
    // джиттер-буфер: кадр в очередь, воспроизведение — по тику micLoop
    // (равномерные 20 мс); без микрофона — прямая запись (фолбэк)
    if (c.pcm == null) return;
    const slot = &c.jbuf[seq % 16];
    @memcpy(&slot.pcm, play);
    slot.have = true;
    if (!c.jinit) {
        c.jinit = true;
        c.jplay_seq = seq;
        c.jfirst_ms = app.nowMs();
    }
}

/// Найти cid по bundle (порядок стабильный: contacts[i] — id i+1).
/// Удалённые чаты невидимы: повторное знакомство с этим человеком создаст
/// НОВЫЙ cid с чистой историей.
fn contactIdByBundle(app: *App, bundle: [64]u8) ?i64 {
    for (app.eng.contacts.items, 0..) |c, i| {
        if (c.deleted) continue;
        if (std.mem.eql(u8, &c.bundle, &bundle)) return @intCast(i + 1);
    }
    return null;
}

/// Открыть аудио (fifo) и запустить поток захвата микрофона.
fn startCallAudio(app: *App, c: *CallState) void {
    if (c.pcm != null) return;
    c.up = true;
    // fifo в ~/.stille-messenger/pcm — файл создаётся при старте чата
    if (app.call_pcm_dir) |dir| {
        if (audio_mod.PcmPort.openFifos(dir)) |p| {
            c.pcm = p;
        } else |_| {}
    }
    c.stop_flag.store(false, .release);
    const th = std.Thread.spawn(.{}, micLoop, .{app}) catch return;
    c.audio_thread = th;
}

/// Поток микрофона: 20 мс кадр -> шифруем -> callAudio. Тишина если fifo пуст.
fn micLoop(app: *App) void {
    // Аккумулятор: fifo может отдавать данные малыми кусками, кадр шлём
    // только целиком (320 байт) — иначе разбор на приёме усложняется.
    var acc: [audio_mod.frame_bytes]u8 = @splat(0); // 640 байт = 20 мс @ 16 кГц
    var acc_len: usize = 0;
    var silent_run: u32 = 0;
    while (true) {
        sysfd.sleepMs(20); // кадр 20 мс
        app.lock();
        defer app.unlock();
        const c = app.call orelse break;
        if (c.stop_flag.load(.acquire)) break;
        if (!c.up) continue;
        if (c.pcm == null) continue; // нет аудио-порта: кадры не шлём
        // добираем в аккумулятор сколько есть
        acc_len += c.pcm.?.readPartial(acc[acc_len..]);
        if (acc_len < audio_mod.frame_bytes) continue; // ждём полный кадр
        const frame_seq = c.seq;
        // seq u32 в кадре CALL_AUDIO: на максимуме ключ/nonce кадра начали бы
        // повторяться — обрываем звонок раньше (практически недостижимо: ~99 суток)
        if (frame_seq == std.math.maxInt(u32)) {
            endCallLocked(app, c.call_id);
            continue;
        }
        // DTX: тишину не шлём (каждый 25-й кадр — keepalive, чтобы пир знал:
        // линия жива). Пустое fifo читается как нули.
        const is_silent = isZero(acc[0..]);
        if (is_silent and silent_run < 24) {
            silent_run += 1;
            acc_len = 0;
            continue;
        }
        silent_run = 0;
        // кодек: IMA-ADPCM 4:1 -> 181 байт на проводе вместо 657
        var wbuf: [1 + audio_mod.adpcm_block + aead_min]u8 = undefined;
        var blk: [audio_mod.adpcm_block]u8 = undefined;
        if (is_silent) {
            @memset(&blk, 0);
        } else {
            _ = adpcm_mod.encodeBlock(&blk, acc[0..]);
        }
        wbuf[0] = audio_mod.codec_adpcm;
        const sealed = audio_mod.sealFrame(wbuf[1..], c.secret, c.call_id, frame_seq, &blk);
        acc_len = 0;
        c.seq = frame_seq + 1;
        _ = app.eng.callAudio(c.cid, frame_seq, wbuf[0 .. 1 + sealed]) catch {};
        jbufTick(app, c);
    }
}

/// Один тик плейаута джиттер-буфера (вызывается из micLoop каждые 20 мс
/// под app.mu). Правила:
///   - ждём накопления 3 кадров ИЛИ стартовой выдержки 60 мс (первый кадр);
///   - перегруз 8+ кадров = слив лишних (задержка не растёт);
///   - дыра дольше 200 мс = пропуск seq (маскирование потери).
fn jbufTick(app: *App, c: *CallState) void {
    if (c.pcm == null or !c.jinit) return;
    var filled: usize = 0;
    for (&c.jbuf) |*sl| {
        if (sl.have) filled += 1;
    }
    const now = app.nowMs();
    const start_ok = filled >= 3 or (now - c.jfirst_ms) >= 60;
    if (!start_ok) return;
    if (filled >= 8) {
        for (&c.jbuf) |*sl| {
            if (sl.have) {
                c.pcm.?.writeFrame(&sl.pcm);
                sl.have = false;
            }
        }
        return;
    }
    const slot = &c.jbuf[c.jplay_seq % 16];
    if (slot.have) {
        c.pcm.?.writeFrame(&slot.pcm);
        slot.have = false;
        c.jplay_seq +%= 1;
        c.jfirst_ms = now; // отсчёт дыры — от последнего сыгранного
    } else if (now - c.jfirst_ms > 200) {
        c.jplay_seq +%= 1;
        c.jfirst_ms = now;
    }
}

const aead_min = 16; // aead.tag_length

fn isZero(b: []const u8) bool {
    for (b) |x| if (x != 0) return false;
    return true;
}

/// Завершить звонок: остановить поток, закрыть аудио, освободить состояние.
fn endCallLocked(app: *App, call_id: [16]u8) void {
    const c = app.call orelse return;
    app.call = null; // micLoop видит null и выходит без обращений к c
    c.stop_flag.store(true, .release);
    c.up = false;
    if (c.audio_thread) |t| {
        app.unlock();
        t.join();
        app.lock();
    }
    if (c.pcm) |*p| p.deinit();
    const cid = c.cid;
    app.alloc.destroy(c);
    evCallState(app, cid, call_id, .end);
}

fn wrapConn(ctx: *anyopaque, raw: interfaces.Conn, keys: stille_messenger.crypto.handshake.SessionKeys, alloc: std.mem.Allocator) anyerror!interfaces.Conn {
    const app: *App = @ptrCast(@alignCast(ctx));
    var key: [32]u8 = undefined;
    stille_messenger.crypto.kdf.expand(keys.transcript, "shopot-obf-v3", &key);
    const oc = try alloc.create(obf.ObfConn);
    oc.* = try obf.ObfConn.init(alloc, app.io, raw, &key);
    app.lock();
    defer app.unlock();
    try app.obfs.append(alloc, oc);
    return obf.obfConn(oc);
}

// ------------------------------------------------------- heartbeat ticker
fn tickerLoop(app: *App) void {
    while (app.running) {
        sysfd.sleepMs(250);
        {
            app.lock();
            defer app.unlock();
            var it = app.hb.iterator();
            const now = app.nowMs();
            while (it.next()) |e| {
                const cid = e.key_ptr.*;
                const st = e.value_ptr;
                const s = app.eng.sessions.get(cid) orelse continue;
                switch (st.tick(now)) {
                    .none => {},
                    .send_ping => |p| s.sendEnvelope(.{ .presence_ping = .{
                        .seq = p.seq,
                        .ts_ms = @intCast(p.ts_ms),
                    } }) catch {},
                    .mark_offline => {
                        app.eng.contacts.items[@intCast(cid - 1)].online = false;
                        if (app.eng.ev.onPresence) |cb|
                            cb(app.eng.ev.ctx, &app.eng.contacts.items[@intCast(cid - 1)], false, now);
                        // молчащая (half-open) сессия мертва: снять с карты —
                        // автодозвон/linker поднимут соединение заново; сам
                        // указатель уйдёт в retired и будет закрыт drain-ом
                        app.eng.retireSession(cid, s);
                    },
                }
            }
        }
        // retired-слив: join rx-потоков и destroy — строго ВНЕ app.mu
        drainRetired(app);
    }
}

/// Закрыть и освободить снятые с карты сессии. Вызывается из тикера БЕЗ
/// app.mu: close() ждёт rx-поток, чей выход берёт лок (join под спин-локом
/// — deadlock). Сессии в retired никому не видны — конкурентных_close нет.
fn drainRetired(app: *App) void {
    var dead: []*session_mod.Session = undefined;
    {
        app.lock();
        defer app.unlock();
        if (app.eng.retired.items.len == 0) return;
        dead = app.eng.retired.toOwnedSlice(app.alloc) catch return;
    }
    for (dead) |s| {
        s.close();
        app.eng.alloc.destroy(s);
    }
    app.alloc.free(dead);
}

/// START_CALL: инициировать звонок. Ответ: [call_id 16].
fn apiStartCall(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME; // лишние байты запрещены
    app.lock();
    defer app.unlock();
    if (app.call != null) return .BUSY;
    if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
    const sess = app.eng.sessions.get(@intCast(cid)) orelse return .NO_SESSION;
    var call_id: [16]u8 = undefined;
    app.io.random(&call_id);
    const c = app.alloc.create(CallState) catch return .INTERNAL;
    c.* = .{ .cid = @intCast(cid), .call_id = call_id, .secret = sess.callSecret(call_id), .start_ms = app.nowMs() };
    app.call = c;
    _ = app.eng.callSignal(@intCast(cid), audio_mod.CallOp.offer, call_id) catch {
        app.alloc.destroy(c);
        app.call = null;
        return .NO_SESSION;
    };
    evCallState(app, @intCast(cid), call_id, .offer);
    w.putBytes(&call_id) catch return .INTERNAL;
    return .OK;
}

/// ANSWER_CALL: принять входящий. Payload пуст, ответ пуст.
fn apiAnswerCall(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    _ = w;
    if (payload.len != 0) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    const c = app.call orelse return .NO_CALL;
    if (c.up) return .OK; // уже в разговоре — идемпотентно
    if (c.start_ms == 0) c.start_ms = app.nowMs();
    _ = app.eng.callSignal(c.cid, audio_mod.CallOp.accept, c.call_id) catch return .NO_SESSION;
    startCallAudio(app, c);
    evCallState(app, c.cid, c.call_id, .accept);
    return .OK;
}

/// END_CALL: завершить/отклонить. Payload пуст, ответ пуст.
fn apiEndCall(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    _ = w;
    if (payload.len != 0) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    const c = app.call orelse return .NO_CALL;
    const call_id = c.call_id;
    _ = app.eng.callSignal(c.cid, audio_mod.CallOp.hangup, call_id) catch {};
    endCallLocked(app, call_id);
    return .OK;
}

// ------------------------------------------------- автоподключение (LAN)
/// Фоновый поток: раз в 2 секунды рассылает анонс (bundle + порт) в
/// мультикаст-группу и слушает чужие. Видит анонс добавленного контакта —
/// сам звонит по TCP. Кто чей bundle меньше — тот инициатор (без дублей).
/// IPv4 в строку (без порта).
fn fmtIpBuf(buf: *[16]u8, ip: [4]u8) []const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch "?";
}

/// Автодозвон офлайн-контактов по сохранённым адресам: backoff 1с -> 60с
/// с джиттером. Пир в LAN — сработает и анонс (linkerLoop); автодозвон
/// покрывает сети без мультикаста и перезагрузки демона. Управляется
/// флагом конфигурации autodial; для линка устройства всегда звонит
/// ДЕРЖАТЕЛЬ кода (ждущая сторона ждёт).
fn autodialLoop(app: *App) void {
    var next_try = std.AutoHashMapUnmanaged(i64, i64).empty;
    defer next_try.deinit(app.alloc);
    var attempts = std.AutoHashMapUnmanaged(i64, u32).empty;
    defer attempts.deinit(app.alloc);
    while (app.running) {
        sysfd.sleepMs(1000);
        const now = app.nowMs();
        // кого звонить: офлайн, есть адрес, время пришло
        var dial_cid: i64 = -1;
        var ab: [80]u8 = undefined;
        var addr_copy: [80]u8 = undefined;
        var addr_len: usize = 0;
        {
            app.lock();
            defer app.unlock();
            if (!app.cfg.autodial) continue;
            for (app.eng.contacts.items, 0..) |*c, i| {
                const cid: i64 = @intCast(i + 1);
                if (app.eng.sessions.get(cid) != null or c.blocked or c.deleted) {
                    _ = attempts.remove(cid);
                    continue;
                }
                // устройство-линк: дозвон только держателем кода (иначе
                // обе стороны звонят одновременно)
                if (c.dev_role != 0 and c.dev_role != dev_role_holder) {
                    _ = attempts.remove(cid);
                    continue;
                }
                const a = c.addr(&ab) orelse continue;
                const nt = next_try.get(cid) orelse 0;
                if (nt > now) continue;
                dial_cid = cid;
                addr_len = a.len;
                @memcpy(addr_copy[0..a.len], a);
                break;
            }
        }
        if (dial_cid >= 0) {
            // single-flight + метка попытки ДО dial (сеть — без app.mu)
            connFlightBegin(app, dial_cid) catch continue;
            var gen: u32 = 0;
            {
                app.lock();
                defer app.unlock();
                gen = connBeginAttemptLocked(app, dial_cid);
            }
            establishTo(app, addr_copy[0..addr_len], dial_cid, .initiator) catch |e| {
                // финальный провал: FAILED + классификация (gen-гейт
                // отбрасывает отставшие рапорты прошлой попытки)
                app.lock();
                defer app.unlock();
                connSetLocked(app, dial_cid, .failed, connErrOf(e), gen);
            };
            connFlightEnd(app, dial_cid);
            // backoff: 1s,2s,4s,8s,16s,32s -> потолок 60s (+ джиттер до 50%)
            app.lock();
            defer app.unlock();
            const at = (attempts.get(dial_cid) orelse 0) + 1;
            attempts.put(app.alloc, dial_cid, at) catch {};
            const shift: u6 = @intCast(@min(at, 6));
            const base: i64 = @as(i64, 1000) << shift;
            const capped: i64 = @min(base, 60_000);
            const jitter: i64 = @mod(now, @divTrunc(capped, 2) + 1);
            next_try.put(app.alloc, dial_cid, now + capped + jitter) catch {};
            // ревизия повтора — в наблюдаемое состояние (next_retry_at)
            if (app.conn_st.getPtr(dial_cid)) |st| {
                st.attempt = at;
                st.next_retry_at = now + capped + jitter;
            }
        }
    }
}

fn linkerLoop(app: *App) void {
    var disc = discover_mod.Discovery.init() catch return;
    defer disc.deinit();
    const my_bundle = app.id.bundle();
    while (app.running) {
        // LAN-поиск управляется конфигурацией: выключен — не анонсим и
        // не слушаем мультикаст (флаг читается под локом на каждой итерации)
        {
            app.lock();
            const lan = app.cfg.lan_discovery;
            app.unlock();
            if (!lan) {
                sysfd.sleepMs(2000);
                continue;
            }
        }
        // анонс ПЕРВЫМ делом итерации: старт демона = immediate-анонс,
        // пир с pending-outbox узнаёт о нас за ~RTT, а не через цикл сна
        disc.announce(my_bundle, app.listen_port);
        var heard: usize = 0;
        while (heard < 8) : (heard += 1) {
            const a = disc.waitAnnounce(300) orelse break;
            // анонс НАШЕГО bundle: другое устройство того же пользователя
            // (device_sync). MACи синхронизации не пустят постороннего, а
            // сюда он и не дойдёт — bundle уникален только у своих.
            if (std.mem.eql(u8, &a.bundle, &my_bundle)) {
                handleDeviceAnnounce(app, a.ip, a.port);
                continue;
            }
            const cid = contactIdByBundle(app, a.bundle) orelse continue;
            // адрес анонса — сохранить для автодозвона (последний известный);
            // мутация контактов — строго под app.mu (ticker и рендер итерируют)
            var ab_ip: [16]u8 = undefined;
            const ip_str = fmtIpBuf(&ab_ip, a.ip);
            {
                app.lock();
                defer app.unlock();
                const c = &app.eng.contacts.items[@intCast(cid - 1)];
                if (c.deleted) continue;
                c.setAddr(ip_str, a.port);
            }
            app.lock();
            const linked = app.eng.sessions.get(cid) != null;
            const blocked = app.eng.contacts.items[@intCast(cid - 1)].blocked;
            const join_due = app.join_map.contains(cid);
            app.unlock();
            if (linked or blocked) continue;
            // инициатор — сторона с меньшим bundle (детерминизм, без гонки);
            // держатель инвайт-кода инициирует ВСЕГДА: приглашающий его не знает
            const i_init = std.mem.order(u8, &my_bundle, &a.bundle) == .lt;
            if (!i_init and !join_due) continue;
            var ab: [32]u8 = undefined;
            const addr = discover_mod.fmtAddr(&ab, a.ip, a.port);
            // markSeen не нужен: establishTo -> bindSession сам метит онлайн.
            // single-flight + метка попытки (2.7.0): dial по анонсу тоже
            // учитывается в attempt/state (gen гасит отставшие рапорты)
            connFlightBegin(app, cid) catch continue;
            const gen: u32 = blk: {
                app.lock();
                defer app.unlock();
                break :blk connBeginAttemptLocked(app, cid);
            };
            establishTo(app, addr, cid, .initiator) catch |e| {
                app.lock();
                defer app.unlock();
                connSetLocked(app, cid, .failed, connErrOf(e), gen);
                connFlightEnd(app, cid);
                continue;
            };
            connFlightEnd(app, cid);
        }
        sysfd.sleepMs(2000);
    }
}

/// Анонс нашего же bundle в LAN: другое устройство пользователя.
/// Дозвон — только ДЕРЖАТЕЛЬ линка (детерминизм, как в join-правиле) и
/// только при включённом device_sync (линк без репликации не нужен;
/// поднять его заново можно кодом инвайта в любой момент).
fn handleDeviceAnnounce(app: *App, ip: [4]u8, port: u16) void {
    var ab_ip: [16]u8 = undefined;
    const ip_str = fmtIpBuf(&ab_ip, ip);
    var dial_cid: i64 = -1;
    {
        app.lock();
        defer app.unlock();
        if (!app.cfg.device_sync) return;
        // v1: один линк-контакт (bundle один на все устройства)
        for (app.eng.contacts.items, 0..) |*c, i| {
            if (!std.mem.eql(u8, &c.bundle, &app.id.bundle())) continue;
            if (c.deleted or c.blocked) return;
            if (c.dev_role != dev_role_holder) return; // мы — ждущая сторона
            if (app.eng.sessions.contains(@intCast(i + 1))) return; // уже жива
            c.setAddr(ip_str, port);
            dial_cid = @intCast(i + 1);
            return;
        }
    }
    if (dial_cid < 0) return;
    var ab: [32]u8 = undefined;
    const addr = discover_mod.fmtAddr(&ab, ip, port);
    // single-flight + метка попытки (2.7.0): как и ручные пути
    connFlightBegin(app, dial_cid) catch return;
    const gen: u32 = blk: {
        app.lock();
        defer app.unlock();
        break :blk connBeginAttemptLocked(app, dial_cid);
    };
    establishTo(app, addr, dial_cid, .initiator) catch |e| {
        app.lock();
        defer app.unlock();
        connSetLocked(app, dial_cid, .failed, connErrOf(e), gen);
    };
    connFlightEnd(app, dial_cid);
}

/// Автолистенер: m1 несёт enc_pk звонящего — опознаём контакт и
/// поднимаем responder-сессию establishIdentified. Не-контакты закрываются.
fn identifyCb(ctx: *anyopaque, enc_pk: [32]u8) ?session_mod.Session.IdentifyResult {
    const app: *App = @ptrCast(@alignCast(ctx));
    for (app.eng.contacts.items) |c| {
        if (std.mem.eql(u8, c.bundle[0..32], &enc_pk)) {
            // удалённый чат мёртв: incoming от него — как от незнакомца
            if (c.deleted) return null;
            // enc_pk нужен для сверки статики в m3 (bundle = enc_pk || sign_pk)
            return .{ .enc_pk = c.bundle[0..32].*, .sign_pk = c.bundle[32..64].* };
        }
    }
    return null;
}

/// Окно pending-join: 3 с на валидный JOIN, иначе сессия закрывается.
fn releasePendingLocked(sc: *SessCtx) void {
    if (!sc.pending_counted) return;
    const app = sc.app;
    if (app.pending_sessions > 0) app.pending_sessions -= 1;
    sc.pending_counted = false;
}

fn releasePending(sc: *SessCtx) void {
    const app = sc.app;
    app.lock();
    releasePendingLocked(sc);
    app.unlock();
}

/// Окно pending-join: 3 с на валидный JOIN, иначе сессия закрывается.
fn joinTimeoutWatch(sc: *SessCtx) void {
    sysfd.sleepMs(3000);
    const app = sc.app;
    app.lock();
    const still_pending = sc.cid == -1;
    app.unlock();
    if (still_pending) {
        releasePending(sc);
        if (sc.s) |sp| sp.close();
    }
}

fn autoAcceptLoop(app: *App, listener: *tcp.Listener) void {
    while (app.running) {
        const tc = listener.accept(app.alloc) catch break;
        {
            app.lock();
            defer app.unlock();
            app.raw_conns.append(app.alloc, tc) catch {
                tc.deinit();
                continue;
            };
        }
        handleAcceptedConn(app, tc);
    }
}

/// Обработка входящего коннекта (TCP-accept ИЛИ спаренный релей-коннект):
/// fake-TLS обёртка -> m1 -> опознание контакта / pending-join по инвайту.
fn handleAcceptedConn(app: *App, tc: *tcp.TcpConn) void {
    // весь провод завёрнут в fake-TLS: обёртку ставим ДО чтения m1,
    // кадр m1 [len u16][64] приходит внутри записей application_data
    const raw = faketlsServer(app, tc) catch {
        tc.deinit();
        return;
    };
    var hdr: [2]u8 = undefined;
    raw.readAll(&hdr) catch {
        tc.deinit();
        return;
    };
    // длина m1 задаёт crypto/handshake.zig (гибрид X25519+ML-KEM-768);
    // чужая/старая версия ядра не сходится в длине кадра — закрываем
    const m1_len = std.mem.readInt(u16, &hdr, .little);
    if (m1_len != stille_messenger.crypto.handshake.m1_len) {
        tc.deinit();
        return;
    }
    var m1: [stille_messenger.crypto.handshake.m1_len]u8 = undefined;
    raw.readAll(&m1) catch {
        tc.deinit();
        return;
    };
    // какой это контакт — узнаем из enc_pk в m1
    var found_cid: i64 = -1;
    {
        app.lock();
        defer app.unlock();
        for (app.eng.contacts.items, 0..) |c, i| {
            if (std.mem.eql(u8, c.bundle[0..32], m1[32..64])) {
                found_cid = @intCast(i + 1);
                break;
            }
        }
    }
    if (found_cid < 0) {
        // держатель инвайт-кода: поднимаем pending-сессию без опознания
        app.lock();
        const has_invite = blk: {
            for (&app.invites) |*reg| {
                if (!reg.used and reg.created_ms != 0) break :blk true;
            }
            break :blk false;
        };
        const pending_slot = has_invite and app.pending_sessions < pending_session_cap;
        if (pending_slot) app.pending_sessions += 1;
        app.unlock();
        if (pending_slot) {
            var eph2: [32]u8 = undefined;
            app.io.random(&eph2);
            const sc = app.alloc.create(SessCtx) catch {
                tc.deinit();
                return;
            };
            sc.* = .{ .app = app, .cid = -1, .s = null, .pending_counted = true };
            const sp = session_mod.Session.establishPending(
                app.alloc,
                raw,
                &m1,
                app.id,
                eph2,
                app,
                wrapConn,
                .{ .ctx = sc, .onEnvelope = envIn, .onClosed = onClosed },
                app.io,
            ) catch {
                app.alloc.destroy(sc);
                tc.deinit();
                return;
            };
            sc.s = sp;
            // окно 3 с: нет валидного JOIN — закрыть
            const tt = std.Thread.spawn(.{}, joinTimeoutWatch, .{sc}) catch {
                sp.close();
                app.alloc.destroy(sc);
                tc.deinit();
                return;
            };
            tt.detach();
        } else {
            tc.deinit();
        }
        return;
    }
    var eph: [32]u8 = undefined;
    app.io.random(&eph);
    const sc = app.alloc.create(SessCtx) catch {
        tc.deinit();
        return;
    };
    sc.* = .{ .app = app, .cid = found_cid };
    const s = session_mod.Session.establishIdentified(
        app.alloc,
        raw,
        &m1,
        app.id,
        eph,
        identifyCb,
        app,
        app,
        wrapConn,
        .{ .ctx = sc, .onEnvelope = envIn, .onClosed = onClosed },
        app.io,
    ) catch {
        app.alloc.destroy(sc);
        tc.deinit();
        return;
    } orelse {
        app.alloc.destroy(sc);
        tc.deinit();
        return;
    };
    app.bindSession(found_cid, s, sc) catch {};
}

fn readRawAll(tc: *tcp.TcpConn, out: []u8) !void {
    var got: usize = 0;
    while (got < out.len) {
        const n = std.posix.read(tc.fd, out[got..]) catch return error.Closed;
        if (n == 0) return error.Closed;
        got += n;
    }
}

// ------------------------------------------------------------- commands

/// Запомнить relay-адрес контакта и поднять presence-поток (один на
/// контакт). ВЫЗЫВАЕТСЯ ПОД app.mu; поток сам ждёт снятия лока.
fn startRelayPresenceLocked(app: *App, cid: i64, addr: []const u8) void {
    if (addr.len == 0) return;
    if (app.contact_relays.getPtr(cid)) |old| {
        if (!std.mem.eql(u8, old.*, addr)) {
            const dup = app.alloc.dupe(u8, addr) catch return;
            app.alloc.free(old.*);
            old.* = dup;
        }
    } else {
        const dup = app.alloc.dupe(u8, addr) catch return;
        app.contact_relays.put(app.alloc, cid, dup) catch {
            app.alloc.free(dup);
            return;
        };
    }
    // тесты: relay-адрес в карте есть (восстановление маршрута
    // проверяемо), но сетевой поток не поднимаем — переживёт тест
    if (app.no_network) return;
    if (app.presence_runs.contains(cid)) return;
    app.presence_runs.put(app.alloc, cid, {}) catch return;
    const th = std.Thread.spawn(.{}, relayPresenceLoop, .{ app, cid, false }) catch {
        _ = app.presence_runs.remove(cid);
        return;
    };
    th.detach();
}

/// Присутствие контакта на СВОЁМ сервере (server_mode): как
/// startRelayPresenceLocked, но адрес — cfg.server_addr (self-hosted
/// релей пользователя), а поток живёт, пока включён server_mode.
/// ВЫЗЫВАЕТСЯ ПОД app.mu; поток сам ждёт снятия лока.
fn startServerPresenceLocked(app: *App, cid: i64) void {
    if (!app.cfg.server_mode) return;
    if (app.cfg.serverAddr().len == 0) return;
    // тесты: сетевые потоки не поднимаем (профиль загружен, сети нет)
    if (app.no_network) return;
    if (app.presence_runs.contains(cid)) return; // персональный релей уже держит слот
    if (app.server_runs.contains(cid)) return;
    app.server_runs.put(app.alloc, cid, {}) catch return;
    const th = std.Thread.spawn(.{}, relayPresenceLoop, .{ app, cid, true }) catch {
        _ = app.server_runs.remove(cid);
        return;
    };
    th.detach();
}

/// server_mode только что включён: поднять присутствие всем живым контактам.
/// ВЫЗЫВАЕТСЯ ПОД app.mu.
fn startServerPresenceForAllLocked(app: *App) void {
    if (!app.cfg.server_mode) return;
    for (app.eng.contacts.items, 0..) |*c, i| {
        if (c.deleted or c.blocked) continue;
        startServerPresenceLocked(app, @intCast(i + 1));
    }
}

/// Поток релей-присутствия контакта: пока контакт жив и не заблокирован,
/// держим регистрацию слота marker-ом из ДОЛГОСРОЧНОГО контакт-секрета
/// (identity.pairSecret -> relay.presenceMarker): пир появляется в релее —
/// спариваемся и поднимаем сессию БЕЗ нового инвайта. Инициатор
/// рукопожатия — сторона с меньшим bundle (детерминизм: обе стороны
/// вычисляют роль одинаково); устройство-линк (bundle равны) — всегда
/// держатель кода. from_server: присутствие на СВОЁМ сервере
/// (server_mode) — адрес перечитывается из конфигурации каждую
/// итерацию, выключение режима гасит поток. Сессия уже жива —
/// регистрация не нужна, ждём её смерти (прямой путь и присутствие
/// не конфликтуют).
fn relayPresenceLoop(app: *App, cid: i64, from_server: bool) void {
    defer {
        app.lock();
        defer app.unlock();
        _ = app.presence_runs.remove(cid);
        _ = app.server_runs.remove(cid);
    }
    var marker: [32]u8 = undefined;
    var me_initiator: bool = false;
    var addr_copy: []u8 = &.{};
    {
        app.lock();
        defer app.unlock();
        const idx = app.eng.findIndex(cid) orelse return;
        const c = &app.eng.contacts.items[idx];
        const sec = app.id.pairSecret(c.bundle) catch return;
        marker = stille_messenger.net.relay.presenceMarker(sec);
        const my_bundle = app.id.bundle();
        if (std.mem.eql(u8, &c.bundle, &my_bundle)) {
            // устройство-близнец: bundle равны, порядок их не разведёт —
            // инициирует держатель линка (как в join-правиле инвайтов)
            me_initiator = c.dev_role == dev_role_holder;
        } else {
            me_initiator = std.mem.order(u8, &my_bundle, &c.bundle) == .lt;
        }
        if (!from_server) {
            const stored = app.contact_relays.get(cid) orelse return;
            addr_copy = app.alloc.dupe(u8, stored) catch return;
        }
    }
    defer {
        if (!from_server) app.alloc.free(addr_copy);
    }
    while (app.running) {
        // адрес dial: персональный релей (фиксирован) или свой сервер
        // (перечитывается — SET_CONFIG может сменить адрес/выключить режим)
        var sb: [config_mod.addr_max]u8 = undefined;
        var sb_len: usize = 0;
        {
            app.lock();
            defer app.unlock();
            const idx = app.eng.findIndex(cid) orelse return; // контакт удалён
            if (app.eng.contacts.items[idx].blocked) return;
            if (app.eng.contacts.items[idx].deleted) return;
            if (from_server) {
                if (!app.cfg.server_mode or !app.server_runs.contains(cid)) return;
                const sa = app.cfg.serverAddr();
                if (sa.len == 0 or sa.len > sb.len) return;
                @memcpy(sb[0..sa.len], sa);
                sb_len = sa.len;
            }
            if (app.eng.sessions.contains(cid)) {
                // живая сессия: присутствие не нужно
                sysfd.sleepMs(1000);
                continue;
            }
        }
        const dial_addr: []const u8 = if (from_server) sb[0..sb_len] else addr_copy;
        // dial блокируется в релее до прихода пира (наш marker — слот)
        const tc = stille_messenger.net.relay.dialMarker(app.alloc, dial_addr, marker) catch {
            sysfd.sleepMs(2000);
            continue;
        };
        {
            app.lock();
            defer app.unlock();
            app.raw_conns.append(app.alloc, tc) catch {
                tc.deinit();
                sysfd.sleepMs(2000);
                continue;
            };
        }
        if (me_initiator) {
            establishSessionOnConn(app, cid, tc) catch {};
        } else {
            // ждём m1 от пира: как TCP-accept
            handleAcceptedConn(app, tc);
        }
        // сессия поднята или упала — цикл проверит и повторит регистрацию
        sysfd.sleepMs(1000);
    }
}

/// Поток A-стороны релея: держит регистрацию marker-ом, пока инвайт жив.
/// Спаривание -> handleAcceptedConn (JOIN поднимет контакт). Обрыв ->
/// переподключение (пир может дозваниваться долго).
fn relayLinkerLoop(app: *App, secret: [16]u8, addr: []const u8) void {
    var secret_copy = secret;
    defer std.crypto.secureZero(u8, &secret_copy);
    const addr_copy = app.alloc.dupe(u8, addr) catch return;
    defer app.alloc.free(addr_copy);
    while (app.running) {
        // инвайт ещё жив? (не redeemed)
        {
            app.lock();
            defer app.unlock();
            var alive = false;
            for (&app.invites) |*reg| {
                if (std.crypto.timing_safe.eql([invite_mod.secret_len]u8, reg.secret, secret_copy) and !reg.used and reg.created_ms != 0) {
                    alive = true;
                    break;
                }
            }
            if (!alive) return;
        }
        const tc = stille_messenger.net.relay.dial(app.alloc, addr_copy, secret_copy) catch {
            sysfd.sleepMs(2000);
            continue;
        };
        {
            app.lock();
            defer app.unlock();
            app.raw_conns.append(app.alloc, tc) catch {
                tc.deinit();
                sysfd.sleepMs(2000);
                continue;
            };
        }
        // спарено: входящий пир (m1+JOIN) — как TCP-accept
        handleAcceptedConn(app, tc);
        // соединение отработало/оборвалось: инвайт ещё жив -> повтор
    }
}

/// CREATE_INVITE: payload [flags u8 (bit0 = relay)][name str16][addr str16].
/// Ответ: [code str16] — односторонний инвайт-код (URL stille://i/...).
fn apiCreateInvite(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const flags = r.readU8() catch return .BAD_FRAME;
    const is_relay = flags & 1 != 0;
    const name_in = r.readStr16() catch return .BAD_FRAME;
    const addr_in = r.readStr16() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    if (name_in.len > invite_mod.max_name) return .BAD_ARGS;
    if (is_relay and addr_in.len == 0) return .BAD_ARGS;
    if (addr_in.len > 64) return .BAD_ARGS;
    const name: []const u8 = if (name_in.len == 0) "stille-messenger" else name_in;
    // односторонний v2-код: держатель добавляется ONE accept-ом
    var secret: [invite_mod.secret_len]u8 = undefined;
    app.io.random(&secret);
    defer std.crypto.secureZero(u8, &secret);
    {
        app.lock();
        defer app.unlock();
        var slot: ?usize = null;
        for (&app.invites, 0..) |*reg, i| {
            if (reg.used or reg.created_ms == 0) {
                slot = i;
                break;
            }
        }
        const i = slot orelse return .TOO_MANY_INVITES;
        app.invites[i] = .{ .secret = secret, .created_ms = app.nowMs(), .used = false };
        if (is_relay) {
            const n = @min(addr_in.len, relay_addr_max);
            @memcpy(app.invites[i].relay_buf[0..n], addr_in[0..n]);
            app.invites[i].relay_len = @intCast(n);
        }
    }
    var out: [256]u8 = undefined;
    var rbuf: [80]u8 = undefined;
    const code_addr: ?[]const u8 = if (is_relay) blk: {
        const s = std.fmt.bufPrint(&rbuf, "r/{s}", .{addr_in}) catch return .BAD_ARGS;
        break :blk s;
    } else if (addr_in.len > 0) addr_in else null;
    const code = invite_mod.encode2(&out, app.id.bundle(), secret, name, code_addr) catch return .BAD_ARGS;
    w.putStr16(code) catch return .INTERNAL;
    if (is_relay) {
        const addr_copy = app.alloc.dupe(u8, addr_in) catch return .INTERNAL;
        if (std.Thread.spawn(.{}, relayLinkerLoop, .{ app, secret, addr_copy })) |t| {
            t.detach();
        } else |_| {
            app.alloc.free(addr_copy);
        }
    }
    return .OK;
}

/// Результат погашения инвайта (общее ядро ACCEPT_INVITE / _EX).
const AcceptOut = struct {
    cid: i64 = 0,
    /// Информирует о постановке работы, НЕ о доверии: контакт
    /// подтверждается только аутентифицированным JOIN.
    disp: api.AcceptDisposition = .accepted,
    state: api.ConnState = .pending,
    attempt: u32 = 0,
};

/// Общее ядро погашения инвайт-кода (v1/v2/v3): разбор, дедуп по bundle,
/// JOIN-данные и постановка работы подключения в планировщик (dial —
/// НЕ в потоке API: ответ уходит сразу). Существующий контакт не
/// дублируется: повторный код возвращает тот же cid.
fn acceptInviteCommon(app: *App, payload: []const u8, out: *AcceptOut) api.Status {
    var r = api.Reader.init(payload);
    const code = r.readStr16() catch return .BAD_FRAME;
    const my_name_in = r.readStr16() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    if (code.len == 0) return .BAD_INVITE_CODE;
    if (my_name_in.len > invite_mod.max_name) return .BAD_ARGS;
    const my_name: []const u8 = if (my_name_in.len == 0) "друг" else my_name_in;

    // разбор: v3 (гибрид i3) или v1/v2
    var bundle: [64]u8 = undefined;
    var name_buf: [invite_mod.max_name]u8 = @splat(0);
    var name_len: usize = 0;
    var addr_buf: [80]u8 = undefined;
    var addr: ?[]const u8 = null;
    var relay_addr_buf: [80]u8 = undefined;
    var relay_addr: ?[]const u8 = null;
    var relay_secret: ?[16]u8 = null;
    var code_secret: [16]u8 = @splat(0);
    var has_code_secret = false; // v2/v3: JOIN-конверт погашает секрет кода
    var hybrid = false;
    if (std.mem.startsWith(u8, code, invite_mod.v3_prefix) or
        std.mem.startsWith(u8, code, invite_mod.legacy_v3_prefix))
    {
        const inv = invite_mod.decode3(code) catch return .BAD_INVITE_CODE;
        bundle = inv.bundle;
        @memcpy(name_buf[0..inv.name_len], inv.name());
        name_len = inv.name_len;
        if (inv.has_direct) {
            addr = inv.direct.addr(&addr_buf) orelse return .BAD_INVITE_CODE;
        }
        if (inv.has_relay) {
            relay_addr = inv.relay.addr(&relay_addr_buf) orelse return .BAD_INVITE_CODE;
            relay_secret = inv.secret;
        }
        code_secret = inv.secret;
        has_code_secret = true;
        hybrid = inv.has_direct and inv.has_relay;
    } else {
        if (!std.mem.startsWith(u8, code, invite_mod.v2_prefix) and
            !std.mem.startsWith(u8, code, invite_mod.legacy_v2_prefix) and
            !std.mem.startsWith(u8, code, "shopot1.")) return .BAD_INVITE_CODE;
        const inv = invite_mod.decode(code) catch return .BAD_INVITE_CODE;
        bundle = inv.bundle;
        @memcpy(name_buf[0..inv.name_len], inv.name());
        name_len = inv.name_len;
        // inv.addr() — только хост: порт живёт отдельно, собираем "host:port"
        if (inv.host_len > 0) {
            addr = std.fmt.bufPrint(&addr_buf, "{s}:{d}", .{ inv.addr().?, inv.port }) catch return .BAD_ARGS;
        }
        if (inv.v2) {
            if (inv.relay) {
                relay_addr = addr;
                relay_secret = inv.secret;
            }
            code_secret = inv.secret;
            has_code_secret = true;
        }
    }
    const name: []const u8 = name_buf[0..name_len];

    // мутации движка/хешмапы — строго под локом (ticker и рендер итерируют)
    var enq: ?ConnWork = null;
    {
        app.lock();
        defer app.unlock();
        // код от НАШЕГО bundle: линк устройства (оба устройства — один сид
        // личности, записи БД реплицируются MAC-ами этого сида).
        // v1: один линк на демон (bundle один на все устройства — второй
        // линок неразличим с первым).
        const is_device = std.mem.eql(u8, &bundle, &app.id.bundle());
        if (is_device and app.sync.devices.count() > 0) return .TOO_BIG;
        const existing = contactIdByBundle(app, bundle);
        if (existing) |ecid| {
            // повторное погашение: тот же cid, дубль не создаётся
            out.cid = ecid;
            if (app.eng.sessions.get(ecid) != null) {
                out.disp = .already_connected;
                out.state = connStateOfLocked(app, ecid);
                out.attempt = if (app.conn_st.get(ecid)) |e| e.attempt else 0;
                return .OK;
            }
            // та же незавершённая работа уже в полёте — не дублируем;
            // ДРУГОЙ секрет на летящую работу — не подменяем (BUSY)
            if (connInflight(app, ecid)) {
                if (has_code_secret) {
                    if (app.join_map.get(ecid)) |ji| {
                        if (!std.mem.eql(u8, &ji.secret, &code_secret)) return .BUSY;
                    }
                }
                out.disp = .already_pending;
                out.state = connStateOfLocked(app, ecid);
                out.attempt = if (app.conn_st.get(ecid)) |e| e.attempt else 0;
                return .OK;
            }
            // новая работа по тому же контакту: адрес обновить
            if (addr) |a| saveContactAddr(app, ecid, a);
            out.cid = ecid;
        } else {
            const idx = app.eng.addContact(name, bundle) catch return .INTERNAL;
            out.cid = @intCast(idx + 1);
            app.hb.put(out.cid, .{}) catch {};
            // держатель кода линка всегда инициирует подключение (детерминизм:
            // bundle устройств равны, порядок их не разведёт)
            if (is_device) {
                app.eng.contacts.items[idx].dev_role = dev_role_holder;
                app.sync.addDevice(out.cid);
            }
            if (addr) |a| saveContactAddr(app, out.cid, a);
            if (app.log) |log| {
                // relay-инвайт: адрес релея в лог — присутствие после рестарта
                logContact(app, log, name, bundle, addr, if (relay_addr != null) relay_addr else null, if (is_device) dev_role_holder else 0);
            }
            // новый контакт: представление изменилось — ревизия
            bumpContactLocked(app, out.cid);
        }
        const cid = out.cid;
        // v2/v3: JOIN-данные — первым конвертом после рукопожатия.
        // Тот же секрет (повтор кода) — идемпотентно; новый секрет
        // заменяет (работы в полёте нет — проверено выше).
        if (has_code_secret) {
            if (app.join_map.getPtr(cid)) |old| {
                std.crypto.secureZero(u8, &old.secret);
            }
            app.join_map.put(app.alloc, cid, .{
                .secret = code_secret,
                .name_len = @intCast(my_name.len),
                .name_buf = blk: {
                    var nb: [32]u8 = @splat(0);
                    @memcpy(nb[0..my_name.len], my_name);
                    break :blk nb;
                },
            }) catch {};
            std.crypto.secureZero(u8, &code_secret);
        }
        // состояние до работы: адрес есть — dial встанет в очередь;
        // адреса нет — ждём LAN-анонс пира (DISCOVERING)
        if (addr == null and relay_addr == null) {
            if (has_code_secret) connSetLocked(app, cid, .pending, .none, null) else connDiscoveringLocked(app, cid);
        } else {
            if (app.conn_st.getPtr(cid)) |st| st.next_retry_at = 0;
        }
        // работа: адрес (прямой/релей) или гибрид
        if (addr != null or relay_addr != null) {
            var work = ConnWork{ .cid = cid };
            if (hybrid) {
                // i3: прямой адрес + relay-fallback (секрет marker-а)
                work.hybrid = true;
                work.relay_secret = relay_secret;
                if (relay_addr) |ra| {
                    if (ra.len <= work.relay_addr_buf.len) {
                        @memcpy(work.relay_addr_buf[0..ra.len], ra);
                        work.relay_addr_len = @intCast(ra.len);
                    }
                }
                if (addr) |a| {
                    if (a.len <= work.addr_buf.len) {
                        @memcpy(work.addr_buf[0..a.len], a);
                        work.addr_len = @intCast(a.len);
                    }
                }
            } else if (relay_secret != null and relay_addr != null) {
                // v2 relay: marker-спаривание
                work.relay_secret = relay_secret;
                if (relay_addr) |ra| {
                    @memcpy(work.addr_buf[0..ra.len], ra);
                    work.addr_len = @intCast(ra.len);
                }
            } else if (addr) |a| {
                @memcpy(work.addr_buf[0..a.len], a);
                work.addr_len = @intCast(a.len);
            }
            enq = work;
        }
        out.state = connStateOfLocked(app, cid);
        out.attempt = if (app.conn_st.get(cid)) |e| e.attempt else 0;
    }
    // постановка в очередь — БЕЗ app.mu (connq_mu — листовый лок)
    if (enq) |work| {
        connEnqueue(app, work) catch {
            // уже в полёте (гонка с другим путём) — это уже_pending
            out.disp = .already_pending;
        };
    }
    return .OK;
}

/// ACCEPT_INVITE: payload [code str16][my_name str16]. Единственное действие
/// держателя кода. Ответ: [cid u32]. Подключение — асинхронно (планировщик
/// 2.7.0): dial не блокирует ответ, стадии видны через GET_CONTACT_STATE /
/// CONTACT_STATE_CHANGED, а статус — по событиям PRESENCE.
fn apiAcceptInvite(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var out = AcceptOut{};
    const st = acceptInviteCommon(app, payload, &out);
    if (st != .OK) return st;
    w.putU32(@intCast(out.cid)) catch return .INTERNAL;
    return .OK;
}

/// ACCEPT_INVITE_EX (44): тот же payload, расширенный ответ:
/// [cid u32][disposition u8][state u8][attempt u32]. disposition
/// информирует о постановке работы, НЕ о доверии (см. PROTOCOL.md §6).
fn apiAcceptInviteEx(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var out = AcceptOut{};
    const st = acceptInviteCommon(app, payload, &out);
    if (st != .OK) return st;
    w.putU32(@intCast(out.cid)) catch return .INTERNAL;
    w.putU8(@backingInt(out.disp)) catch return .INTERNAL;
    w.putU8(@backingInt(out.state)) catch return .INTERNAL;
    w.putU32(out.attempt) catch return .INTERNAL;
    return .OK;
}

/// GET_IDENTITY: свои публичные данные (сверка отпечатка голосом/QR).
/// Ответ: [bundle 64][fingerprint 32]. На непровиженном профиле —
/// NOT_INITIALIZED: GUI показывает онбординг, а не эфемерный bundle.
fn apiGetIdentity(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    if (payload.len != 0) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    if (!app.provisioned) return .NOT_INITIALIZED;
    const bundle = app.id.bundle();
    var digest: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(&bundle, &digest, .{});
    w.putBytes(&bundle) catch return .INTERNAL;
    w.putBytes(&digest) catch return .INTERNAL;
    return .OK;
}

/// LIST_CONTACTS: все контакты. Ответ:
/// [count u32] × {[cid u32][flags u8 bit0 online bit1 blocked]
/// [last_seen_ms i64 (0 = неизвестно)][name str16]}.
fn apiListContacts(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    if (payload.len != 0) return .BAD_FRAME;
    const max_contacts = 10000;
    app.lock();
    defer app.unlock();
    if (app.eng.contacts.items.len > max_contacts) return .TOO_BIG;
    // удалённые чаты (слоты-надгробия) в списке не видны
    var n: usize = 0;
    for (app.eng.contacts.items) |c| {
        if (!c.deleted) n += 1;
    }
    w.putU32(@intCast(n)) catch return .INTERNAL;
    for (app.eng.contacts.items, 0..) |c, i| {
        if (c.deleted) continue;
        const cid: i64 = @intCast(i + 1);
        var flags: u8 = 0;
        if (c.online) flags |= 1;
        if (c.blocked) flags |= 2;
        const seen: i64 = app.eng.lastSeen(cid) orelse 0;
        w.putU32(@intCast(cid)) catch return .INTERNAL;
        w.putU8(flags) catch return .INTERNAL;
        w.putI64(seen) catch return .INTERNAL;
        w.putStr16(c.getName()) catch return .INTERNAL;
    }
    return .OK;
}

/// Состояние приёма одного файла (FILE_META + чанки FILE_DATA).
const RxFile = struct {
    name_buf: [envelope.max_file_name]u8 = @splat(0),
    name_len: usize = 0,
    size: u32 = 0,
    sha: [32]u8 = @splat(0),
    expected_seq: u32 = 0,
    buf: std.ArrayListUnmanaged(u8) = .empty,

    fn name(self: *const RxFile) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

/// Обернуть TCP-коннект в fake-TLS (server-роль, accept-сторона).
/// use_fake_tls = false: сырой TCP — обфускация и AEAD остаются, но
/// провод больше не похож на TLS (сеть без TLS-подобного трафика).
/// ОБЕ стороны обязаны совпадать по настройке, иначе рукопожатие
/// не сойдётся (старые записи fake-TLS читаются как мусор m1).
fn faketlsServer(app: *App, tc: *tcp.TcpConn) !interfaces.Conn {
    {
        app.lock();
        defer app.unlock();
        if (!app.cfg.use_fake_tls) return tc.conn();
    }
    const ft = stille_messenger.net.faketls.wrap(app.alloc, app.io, tc.conn(), .server) catch |e| {
        return e;
    };
    {
        app.lock();
        defer app.unlock();
        app.ftlss.append(app.alloc, ft.ftls) catch {
            ft.ftls.deinit();
            app.alloc.destroy(ft.ftls);
            return error.OutOfMemory;
        };
    }
    return ft.conn;
}

fn establishTo(app: *App, addr: []const u8, cid: i64, role: session_mod.HandshakeRole) !void {
    return establishToRelay(app, addr, .{ .cid = cid, .role = role });
}

/// Опции установления соединения (establishToRelay).
const EstablishOpts = struct {
    cid: i64,
    role: session_mod.HandshakeRole = .initiator,
    /// secret релея: адрес — релей, подключение через marker-спаривание
    /// (пир не видит наш IP).
    relay_secret: ?[16]u8 = null,
    /// Поколение попытки для stage-меток (null — системный вызов без
    /// метки: автодозвон/linker ставят её через connBeginAttemptLocked).
    gen: ?u32 = null,
    /// Таймаут прямого dial в мс (0 — блокирующий dial без дедлайна;
    /// гибрид-инвайты i3 ставят окно direct_dial_timeout_ms).
    dial_timeout_ms: u32 = 0,
};

/// establishTo с опциональным релеем: secret != null — адрес это релей,
/// подключение через marker-спаривание (пир не видит наш IP).
/// Прямые dial при включённом use_tor_mask идут через Tor SOCKS5
/// (релей-подключения Tor не используют: релей и так скрывает IP).
/// Стадии подключения (handshaking после dial) отмечаются в conn_st.
fn establishToRelay(app: *App, addr: []const u8, opts: EstablishOpts) !void {
    // конфиг читаем под локом (SET_CONFIG меняет на живом демоне)
    var tor_buf: [config_mod.addr_max]u8 = undefined;
    var tor_len: usize = 0;
    if (opts.relay_secret == null and opts.dial_timeout_ms == 0) {
        app.lock();
        defer app.unlock();
        if (app.cfg.use_tor_mask) {
            const ta = app.cfg.torAddr();
            if (ta.len == 0) return error.NoTor;
            @memcpy(tor_buf[0..ta.len], ta);
            tor_len = ta.len;
        }
    }
    const tc = if (opts.relay_secret) |sec|
        stille_messenger.net.relay.dial(app.alloc, addr, sec) catch return error.NoRelay
    else if (opts.dial_timeout_ms > 0)
        try dialDeadline(app, addr, opts.dial_timeout_ms)
    else if (tor_len > 0)
        socks5.dial(app.alloc, tor_buf[0..tor_len], addr) catch return error.NoTor
    else
        try tcp.dial(app.alloc, addr);
    {
        app.lock();
        defer app.unlock();
        try app.raw_conns.append(app.alloc, tc);
        // транспорт поднят: стадия handshaking (метка поколения попытки)
        if (opts.gen) |g| connSetLocked(app, opts.cid, .handshaking, .none, g);
    }
    if (opts.role != .initiator) {
        // responder через релей: ждём m1 как accept
        handleAcceptedConn(app, tc);
        return;
    }
    try establishSessionOnConn(app, opts.cid, tc);
}

/// Поднять сессию ИНИЦИАТОРОМ на уже подключённом конне (relay-присутствие
/// и establishToRelay): fake-TLS client (настраивается), рукопожатие, bind.
fn establishSessionOnConn(app: *App, cid: i64, tc: *tcp.TcpConn) !void {
    const idx: usize = @intCast(cid - 1);
    if (idx >= app.eng.contacts.items.len) return error.NoContact;
    const bundle = app.eng.contacts.items[idx].bundle;
    var eph: [32]u8 = undefined;
    app.io.random(&eph);
    const sc = try app.alloc.create(SessCtx);
    sc.* = .{ .app = app, .cid = cid };
    // транспортная маскировка под TLS (dialer = client-роль fake-TLS);
    // выключена — сырой TCP поверх tc (обфускация и AEAD остаются)
    var fake_tls: bool = false;
    {
        app.lock();
        defer app.unlock();
        fake_tls = app.cfg.use_fake_tls;
    }
    var transport: interfaces.Conn = undefined;
    if (fake_tls) {
        const ft = stille_messenger.net.faketls.wrap(app.alloc, app.io, tc.conn(), .client) catch |e| {
            app.alloc.destroy(sc);
            return e;
        };
        {
            app.lock();
            defer app.unlock();
            app.ftlss.append(app.alloc, ft.ftls) catch {
                ft.ftls.deinit();
                app.alloc.destroy(ft.ftls);
                app.alloc.destroy(sc);
                return error.OutOfMemory;
            };
        }
        transport = ft.conn;
    } else {
        transport = tc.conn();
    }
    const s = session_mod.Session.establish(
        app.alloc,
        transport,
        .initiator,
        app.id,
        bundle,
        eph,
        app,
        wrapConn,
        .{ .ctx = sc, .onEnvelope = envIn, .onClosed = onClosed },
        app.io,
    ) catch |e| {
        app.alloc.destroy(sc);
        return e;
    };
    // держатель инвайта: JOIN — ПЕРВЫМ конвертом, до bind/PROFILE:
    // пир-сторона в pending-режиме закрывает соединение на любом конверте,
    // кроме JOIN. До PROFILE-эха контакт НЕ считается подтверждённым.
    const join_sent = sendJoinIfDue(app, cid, s);
    if (join_sent) {
        // окно ожидания PROFILE-эха (подтверждение добавления): бинд
        // отметит JOINING; эхо/таймаут переведут в ONLINE
        app.lock();
        defer app.unlock();
        const deadline = app.nowMs() + @as(i64, @intCast(join_echo_timeout_ms));
        app.conn_await.put(app.alloc, cid, deadline) catch {};
    }
    try app.bindSession(cid, s, sc);
    if (join_sent) {
        const th = std.Thread.spawn(.{}, joinEchoWatch, .{ app, cid }) catch null;
        if (th) |t| t.detach();
    }
}

/// Отправка JOIN по join_map (после установления сессии). true — JOIN
/// отправлен (данные погашены в join_map, ждём PROFILE-эхо). Отказ
/// отправки НЕ гасит данные: следующая попытка подключения отправит JOIN
/// заново (секрет одноразовый только на стороне ПРИГЛАШАЮЩЕГО).
fn sendJoinIfDue(app: *App, cid: i64, s: *session_mod.Session) bool {
    var ji: JoinInfo = undefined;
    var bundle: [64]u8 = undefined;
    var transcript: [32]u8 = undefined;
    app.lock();
    const stored = app.join_map.get(cid) orelse {
        app.unlock();
        return false;
    };
    ji = stored;
    bundle = app.id.bundle();
    transcript = s.keys.transcript;
    app.unlock();

    var sig: [64]u8 = undefined;
    app.id.sign(&transcript, &sig) catch {
        std.crypto.secureZero(u8, &ji.secret);
        return false;
    };
    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, &transcript, &ji.secret);
    const j = envelope.Join{
        .bundle = bundle,
        .name = ji.name(),
        .sig = sig,
        .hmac = mac,
    };
    s.sendEnvelope(.{ .join = j }) catch {
        // отправка не удалась: JOIN-данные остаются в join_map —
        // повторная попытка подключения отправит JOIN заново
        std.crypto.secureZero(u8, &ji.secret);
        return false;
    };
    app.lock();
    if (app.join_map.getPtr(cid)) |pending| {
        // Удаляем только ту же заявку; повторный ACCEPT с новым ключом
        // не должен быть погашен старой отправкой.
        if (std.crypto.timing_safe.eql([invite_mod.secret_len]u8, pending.secret, ji.secret)) {
            std.crypto.secureZero(u8, &pending.secret);
            _ = app.join_map.remove(cid);
        }
    }
    app.unlock();
    std.crypto.secureZero(u8, &ji.secret);
    return true;
}

/// Окно PROFILE-эха после JOIN истекло: сессия аутентифицирована —
/// ONLINE (код join_timeout фиксируется как диагностика; PROFILE —
/// наблюдаемый признак, НЕ криптографическая квитанция JOIN).
fn joinEchoWatch(app: *App, cid: i64) void {
    sysfd.sleepMs(join_echo_timeout_ms);
    app.lock();
    defer app.unlock();
    if (app.conn_await.remove(cid)) {
        if (app.eng.sessions.get(cid) != null) {
            connSetLocked(app, cid, .online, .join_timeout, null);
        } else {
            connSetLocked(app, cid, .failed, .join_timeout, null);
        }
    }
}

fn acceptLoop(app: *App, listener: *tcp.Listener, cid: i64) void {
    while (app.running) {
        const tc = listener.accept(app.alloc) catch break;
        {
            app.lock();
            defer app.unlock();
            app.raw_conns.append(app.alloc, tc) catch {
                tc.deinit();
                continue;
            };
        }
        const idx: usize = @intCast(cid - 1);
        const bundle = app.eng.contacts.items[idx].bundle;
        var eph: [32]u8 = undefined;
        app.io.random(&eph);
        const sc = app.alloc.create(SessCtx) catch {
            tc.deinit();
            continue;
        };
        sc.* = .{ .app = app, .cid = cid };
        const raw = faketlsServer(app, tc) catch {
            app.alloc.destroy(sc);
            tc.deinit();
            continue;
        };
        const s = session_mod.Session.establish(
            app.alloc,
            raw,
            .responder,
            app.id,
            bundle,
            eph,
            app,
            wrapConn,
            .{ .ctx = sc, .onEnvelope = envIn, .onClosed = onClosed },
            app.io,
        ) catch {
            app.alloc.destroy(sc);
            continue;
        };
        app.bindSession(cid, s, sc) catch {};
    }
}

/// SEND_MESSAGE: payload [cid u32][body str16 ≤4096][ent_count u8]
/// × {[kind u8][offset u16][len u16][value_len u8][value]}.
/// Ответ: [msg_id 16][flags u8 (bit0 = queued)]. Отправка офлайн — НЕ ошибка.
fn apiSendMessage(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    const body = r.readStr16() catch return .BAD_FRAME;
    if (body.len == 0 or body.len > envelope.max_text_body) return .BAD_ARGS;
    // хвост entities = остаток payload (структурно обрезан — BAD_FRAME,
    // семантика неверна — BAD_ARGS)
    var ents: [envelope.max_text_entities]envelope.TextEntity = undefined;
    const n = envelope.parseEntities(r.buf[r.pos..], body.len, &ents) catch |e| switch (e) {
        error.Truncated, error.BadLen => return .BAD_FRAME,
        else => return .BAD_ARGS,
    };
    app.lock();
    defer app.unlock();
    if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
    if (app.eng.contacts.items[cid - 1].deleted) return .NO_CONTACT;
    const oc = app.eng.sendText(@intCast(cid), body, ents[0..n]) catch |e| return statusOf(e);
    // delivered в истории = подтверждено ACK (не «улетело в сокет»):
    // погашение пишет persistOutboxAck по событию MESSAGE_DELIVERED
    persistMsg(app, @intCast(cid), true, oc.msg_id, null, false, app.nowMs(), body, ents[0..n]);
    if (oc.result == .queued) persistOutboxAdd(app);
    w.putBytes(&oc.msg_id) catch return .INTERNAL;
    w.putU8(if (oc.result == .queued) 1 else 0) catch return .INTERNAL;
    return .OK;
}

/// SEND_REPLY_MESSAGE: payload [cid u32][reply_to_msg_hex str16][body str16]
/// followed by the same entity tail as SEND_MESSAGE. The reference is exactly
/// 32 hexadecimal characters and must identify a message in this chat.
fn apiSendReplyMessage(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    const ref = r.readStr16() catch return .BAD_FRAME;
    const reply_to = parseMsgIdHex(ref) orelse return .BAD_ARGS;
    const body = r.readStr16() catch return .BAD_FRAME;
    if (body.len == 0 or body.len > envelope.max_text_body) return .BAD_ARGS;
    var ents: [envelope.max_text_entities]envelope.TextEntity = undefined;
    const n = envelope.parseEntities(r.buf[r.pos..], body.len, &ents) catch |e| switch (e) {
        error.Truncated, error.BadLen => return .BAD_FRAME,
        else => return .BAD_ARGS,
    };
    app.lock();
    defer app.unlock();
    if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
    if (app.eng.contacts.items[cid - 1].deleted) return .NO_CONTACT;
    const target = app.hist_idx.get(reply_to) orelse return .NOT_FOUND;
    const target_rec = app.hist.items[target];
    if (std.mem.readInt(u16, target_rec[0..2], .little) != cid) return .NOT_FOUND;
    const oc = app.eng.sendReplyText(@intCast(cid), reply_to, body, ents[0..n]) catch |e| return statusOf(e);
    persistMsg(app, @intCast(cid), true, oc.msg_id, reply_to, false, app.nowMs(), body, ents[0..n]);
    if (oc.result == .queued) persistOutboxAdd(app);
    w.putBytes(&oc.msg_id) catch return .INTERNAL;
    w.putU8(if (oc.result == .queued) 1 else 0) catch return .INTERNAL;
    return .OK;
}

/// SET_REACTION / REMOVE_REACTION: payload [cid u32][msg_id 16][codepoint u32].
/// codepoint вне U+0000..U+10FFFF — UNSUPPORTED_REACTION. Ответ пуст.
fn apiReaction(app: *App, payload: []const u8, add: bool) api.Status {
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    const mid: [16]u8 = (r.readBytes(16) catch return .BAD_FRAME)[0..16].*;
    const code = r.readU32() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    if (code > 0x10FFFF) return .UNSUPPORTED_REACTION;
    app.lock();
    defer app.unlock();
    if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
    const op: u8 = if (add) envelope.react_add else envelope.react_remove;
    app.eng.react(@intCast(cid), mid, op, code) catch |e| return statusOf(e);
    persistReact(app, @intCast(cid), true, mid, op, code, app.nowMs());
    return .OK;
}

/// BLOCK_CONTACT / UNBLOCK_CONTACT: payload [cid u32]. Ответ пуст.
fn apiBlock(app: *App, payload: []const u8, flag: bool) api.Status {
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
    if (flag) {
        app.eng.block(@intCast(cid)) catch |e| return statusOf(e);
    } else {
        app.eng.unblock(@intCast(cid)) catch |e| return statusOf(e);
        // разблокировка: вернуть релей-присутствие, если было
        if (app.contact_relays.get(@as(i64, @intCast(cid)))) |ra| {
            startRelayPresenceLocked(app, @intCast(cid), ra);
        }
    }
    if (app.log) |log| {
        var buf: [65]u8 = undefined;
        @memcpy(buf[0..64], &app.eng.contacts.items[cid - 1].bundle);
        buf[64] = @intFromBool(flag);
        _ = log.append(.block, &buf) catch {};
        syncEnqueue(app, @backingInt(sync_mod.RecKind.block), &buf);
        syncPumpLocked(app);
    }
    // 2.7.0: флаг блокировки — часть представления контакта
    bumpContactLocked(app, @intCast(cid));
    return .OK;
}

// --------------------------------------------- закрепления и удаление чатов

/// Капа закреплённых сообщений на чат.
const max_pinned_msgs = 16;

/// PIN_CHAT (25): [cid u32] → ∅. Закреплённый чат один на ядро,
/// переживает рестарт (set:3/set:4).
fn apiPinChat(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    _ = w;
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
    if (app.eng.contacts.items[cid - 1].deleted) return .NO_CONTACT;
    app.pinned_chat = cid;
    if (app.log) |log| {
        var buf: [3]u8 = undefined;
        buf[0] = 3;
        std.mem.writeInt(u16, buf[1..3], @intCast(cid), .little);
        _ = log.append(.set, &buf) catch {};
    }
    return .OK;
}

/// GET_PINNED_CHAT (26): ∅ → [cid u32] (0 — не закреплено).
fn apiGetPinnedChat(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    if (payload.len != 0) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    var cid: u32 = 0;
    if (app.pinned_chat >= 1 and app.pinned_chat <= app.eng.contacts.items.len) {
        if (!app.eng.contacts.items[@intCast(app.pinned_chat - 1)].deleted) {
            cid = @intCast(app.pinned_chat);
        }
    }
    w.putU32(cid) catch return .INTERNAL;
    return .OK;
}

/// UNPIN_CHAT (27): ∅ → ∅. Идемпотентно.
fn apiUnpinChat(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    _ = w;
    if (payload.len != 0) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    app.pinned_chat = 0;
    if (app.log) |log| {
        const buf = [_]u8{4};
        _ = log.append(.set, &buf) catch {};
    }
    return .OK;
}

/// DELETE_CHAT (28): [cid u32] → ∅. Слот контакта остаётся (cid стабильны
/// до рестарта), но контакт невидим и мёртв: сессия снята, outbox/файлы/
/// история/закрепления очищены, автодозвон и линкер его не трогают.
/// Переживает рестарт (set:7 по bundle). Повторное знакомство — новый cid
/// с чистой историей.
fn apiDeleteChat(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    _ = w;
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
    const c = &app.eng.contacts.items[cid - 1];
    if (c.deleted) return .NO_CONTACT;
    // сессия — в retired (drain закроет и освободит)
    if (app.eng.sessions.get(@intCast(cid))) |s| app.eng.retireSession(@intCast(cid), s);
    _ = app.sess_ctx.remove(@intCast(cid));
    // очередь недоставленных
    var i: usize = 0;
    while (i < app.eng.outbox.items.len) {
        if (app.eng.outbox.items[i].cid == cid) {
            const e = app.eng.outbox.orderedRemove(i);
            app.alloc.free(e.body);
            app.alloc.free(e.ents_tail);
        } else i += 1;
    }
    // исходящие файлы в полёте
    var j: usize = 0;
    while (j < app.eng.file_tx.items.len) {
        if (app.eng.file_tx.items[j].cid == cid) {
            var f = app.eng.file_tx.orderedRemove(j);
            std.crypto.secureZero(u8, &f.sha);
            app.alloc.free(f.name);
            app.alloc.free(f.data);
        } else j += 1;
    }
    // история (кэш), реакции не трогаем — записи без cid-хозяина
    // невидимы: GET_MESSAGE удалённых чатов не бывает
    histPurgeFor(app, cid);
    // закрепления
    if (app.pinned_chat == cid) app.pinned_chat = 0;
    if (app.pinned_msgs.fetchRemove(cid)) |kv| {
        var list = kv.value;
        list.deinit(app.alloc);
    }
    // presence-состояния
    _ = app.hb.remove(cid);
    if (app.eng.seen.fetchRemove(cid)) |kv| {
        var seen = kv.value;
        seen.deinit(app.alloc);
    }
    _ = app.eng.last_seen_ms.remove(cid);
    if (app.contact_relays.fetchRemove(cid)) |kv| {
        app.alloc.free(kv.value);
    }
    // надгробие: при загрузке слот cid станет невидимым (bundle не годится:
    // повторное знакомство с тем же человеком — ДРУГОЙ слот, надгробие по
    // bundle съело бы и его)
    c.deleted = true;
    c.online = false;
    // линк устройства: снять регистрацию (очередь синхронизации очищается;
    // запись device-линка в логе помечена dev_role и не восстановится)
    if (c.dev_role != 0) app.sync.removeDevice(@intCast(cid));
    if (app.log) |log| {
        var buf: [3]u8 = undefined;
        buf[0] = 7;
        std.mem.writeInt(u16, buf[1..3], @intCast(cid), .little);
        _ = log.append(.set, &buf) catch {};
    }
    // 2.7.0: удаление — REMOVED-ревизия; летящая работа увидит deleted
    // и погаснет (canceled), ожидание эха — снять
    _ = app.conn_await.remove(@as(i64, @intCast(cid)));
    bumpRemovedLocked(app, @intCast(cid));
    return .OK;
}

/// SEND_CONTACT (29): [to_cid u32][contact_cid u32 (0 = моя карточка)] → ∅.
/// Отправляет конверт CONTACT_CARD по живой сессии; получатель видит
/// событие CONTACT_CARD. Добавить человека из карточки можно только его
/// собственным инвайтом — карточка знакомит, не подключает.
fn apiSendContact(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    _ = w;
    var r = api.Reader.init(payload);
    const to_cid = r.readU32() catch return .BAD_FRAME;
    const contact_cid = r.readU32() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    if (to_cid < 1 or to_cid > app.eng.contacts.items.len) return .NO_CONTACT;
    const to = &app.eng.contacts.items[to_cid - 1];
    if (to.deleted) return .NO_CONTACT;
    if (to.blocked) return .CONTACT_BLOCKED;
    var name_buf: [32]u8 = undefined;
    var name_len: usize = 0;
    var bundle: [64]u8 = undefined;
    var ab: [80]u8 = undefined;
    var card_addr: []const u8 = "";
    if (contact_cid == 0) {
        // своя карточка: имя профиля + свой bundle
        const my_name = app.eng.myName();
        @memcpy(name_buf[0..my_name.len], my_name);
        name_len = my_name.len;
        bundle = app.id.bundle();
    } else {
        if (contact_cid > app.eng.contacts.items.len) return .NO_CONTACT;
        const c = &app.eng.contacts.items[contact_cid - 1];
        if (c.deleted) return .NO_CONTACT;
        const cname = c.getName();
        @memcpy(name_buf[0..cname.len], cname);
        name_len = cname.len;
        bundle = c.bundle;
        if (c.addr(&ab)) |a| card_addr = a;
    }
    const s = app.eng.sessions.get(@intCast(to_cid)) orelse return .NO_SESSION;
    s.sendEnvelope(.{ .contact_card = .{
        .name = name_buf[0..name_len],
        .bundle = bundle,
        .addr = card_addr,
    } }) catch return .NO_SESSION;
    return .OK;
}

/// PIN_MESSAGE (30): [cid u32][msg_id 16] → ∅. Сообщение обязано быть в
/// истории чата; капа max_pinned_msgs на чат. Переживает рестарт (set:5).
fn apiPinMessage(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    _ = w;
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    const msg_id: [16]u8 = (r.readBytes(16) catch return .BAD_FRAME)[0..16].*;
    if (r.hasMore()) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
    if (app.eng.contacts.items[cid - 1].deleted) return .NO_CONTACT;
    const list = app.pinned_msgs.getOrPut(app.alloc, @intCast(cid)) catch return .INTERNAL;
    if (!list.found_existing) list.value_ptr.* = .empty;
    for (list.value_ptr.items) |m| {
        if (std.mem.eql(u8, &m, &msg_id)) return .OK; // уже закреплено
    }
    // сообщение из этого чата?
    const idx = app.hist_idx.get(msg_id) orelse return .NOT_FOUND;
    const rec = app.hist.items[idx];
    if (rec.len < 2 or std.mem.readInt(u16, rec[0..2], .little) != cid) return .NOT_FOUND;
    if (list.value_ptr.items.len >= max_pinned_msgs) return .TOO_BIG;
    list.value_ptr.append(app.alloc, msg_id) catch return .INTERNAL;
    if (app.log) |log| {
        var buf: [19]u8 = undefined;
        buf[0] = 5;
        std.mem.writeInt(u16, buf[1..3], @intCast(cid), .little);
        @memcpy(buf[3..19], &msg_id);
        _ = log.append(.set, &buf) catch {};
    }
    return .OK;
}

/// UNPIN_MESSAGE (31): [cid u32][msg_id 16] → ∅. Идемпотентно (set:6).
fn apiUnpinMessage(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    _ = w;
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    const msg_id: [16]u8 = (r.readBytes(16) catch return .BAD_FRAME)[0..16].*;
    if (r.hasMore()) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
    if (app.pinned_msgs.getPtr(@intCast(cid))) |list| {
        var i: usize = 0;
        while (i < list.items.len) : (i += 1) {
            if (std.mem.eql(u8, &list.items[i], &msg_id)) {
                _ = list.orderedRemove(i);
                break;
            }
        }
    }
    if (app.log) |log| {
        var buf: [19]u8 = undefined;
        buf[0] = 6;
        std.mem.writeInt(u16, buf[1..3], @intCast(cid), .little);
        @memcpy(buf[3..19], &msg_id);
        _ = log.append(.set, &buf) catch {};
    }
    return .OK;
}

/// GET_PINNED_MESSAGES (32): [cid u32] → [count u32] × {[msg_id 16]}
/// в порядке закрепления.
fn apiGetPinnedMessages(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
    if (app.eng.contacts.items[cid - 1].deleted) return .NO_CONTACT;
    const list = app.pinned_msgs.get(@intCast(cid)) orelse {
        w.putU32(0) catch return .INTERNAL;
        return .OK;
    };
    w.putU32(@intCast(list.items.len)) catch return .INTERNAL;
    for (list.items) |m| {
        w.putBytes(&m) catch return .INTERNAL;
    }
    return .OK;
}

/// Закодировать контактную запись формата лога (kind contact) в `buf`;
/// вернуть длину. Имя ≤ 32, хвосты: [alen][host][port u16 LE] адреса,
/// [rlen][rhost][rport u16 LE] релея, затем байт роли линка устройства
/// (пишется только для устройств; старые читатели хвост не знают).
/// Используется логом (logContact) и recovery-пакетом (app/recovery.zig).
pub fn encodeContactRecord(buf: []u8, name: []const u8, bundle: [64]u8, addr_: ?[]const u8, relay_addr: ?[]const u8, dev_role: u8) usize {
    const a: []const u8 = addr_ orelse "";
    const ra: []const u8 = relay_addr orelse "";
    var n: usize = 0;
    buf[0] = @intCast(name.len);
    n = 1;
    @memcpy(buf[n .. n + name.len], name);
    n += name.len;
    @memcpy(buf[n .. n + 64], &bundle);
    n += 64;
    // хвост адреса: [alen][host][port u16 LE] (для совместимости со старыми логами)
    const host_port = splitHostPort(a);
    const alen = host_port.host.len;
    if (alen > 0 and alen <= 64) {
        buf[n] = @intCast(alen);
        n += 1;
        @memcpy(buf[n .. n + alen], host_port.host);
        n += alen;
        std.mem.writeInt(u16, buf[n..][0..2], host_port.port, .little);
        n += 2;
    }
    // хвост relay-адреса: [rlen][rhost][rport u16 LE] (старые логи короче)
    const rhp = splitHostPort(ra);
    if (rhp.host.len > 0 and rhp.host.len <= 64) {
        buf[n] = @intCast(rhp.host.len);
        n += 1;
        @memcpy(buf[n .. n + rhp.host.len], rhp.host);
        n += rhp.host.len;
        std.mem.writeInt(u16, buf[n..][0..2], rhp.port, .little);
        n += 2;
    }
    // хвост роли линка устройства: пишется только для устройств (старые
    // читатели хвост не знают, новые — читают только при наличии байта)
    if (dev_role != 0 and n < buf.len) {
        buf[n] = dev_role;
        n += 1;
    }
    return n;
}

/// Записать контакт в лог (с адресом, если известен; relay_addr — хвост
/// [rlen][rhost][rport LE] для восстановления присутствия после рестарта;
/// dev_role — хвостовой байт роли линка устройства, 0 = не устройство).
fn logContact(app: *App, log: *store_mod.Log, name: []const u8, bundle: [64]u8, addr_: ?[]const u8, relay_addr: ?[]const u8, dev_role: u8) void {
    // 232 = максимум записи (имя 32 + bundle + оба хвоста + роль линка)
    var buf: [232]u8 = undefined;
    const n = encodeContactRecord(&buf, name, bundle, addr_, relay_addr, dev_role);
    _ = log.append(.contact, buf[0..n]) catch {};
    syncEnqueue(app, @backingInt(sync_mod.RecKind.contact), buf[0..n]);
    syncPumpLocked(app);
}

const HostPort = struct { host: []const u8, port: u16 };

/// "host:port" -> {host, port}; без порта — port 0.
fn splitHostPort(a: []const u8) HostPort {
    if (std.mem.lastIndexOfScalar(u8, a, ':')) |c| {
        const port = std.fmt.parseInt(u16, a[c + 1 ..], 10) catch 0;
        return .{ .host = a[0..c], .port = port };
    }
    return .{ .host = a, .port = 0 };
}

/// Запомнить адрес контакта (в памяти и логе).
fn saveContactAddr(app: *App, cid: i64, host_port_str: []const u8) void {
    const hp = splitHostPort(host_port_str);
    const c = &app.eng.contacts.items[@intCast(cid - 1)];
    if (hp.port == 0) return;
    // не перезаписываем адрес логом при каждом чихе — только если изменился
    if (c.addr_len == hp.host.len and c.addr_port == hp.port and
        std.mem.eql(u8, c.addr_buf[0..c.addr_len], hp.host)) return;
    c.setAddr(hp.host, hp.port);
    if (app.log) |log| {
        // не теряем relay-хвост и роль линка при перезаписи адреса
        const relay_saved = app.contact_relays.get(cid);
        logContact(app, log, c.getName(), c.bundle, host_port_str, relay_saved, c.dev_role);
    }
}

/// Записать в лог последнюю запись outbox (вызов ПОД локом сразу после
/// sendText == .queued: она наша, очередь под локом).
fn persistOutboxAdd(app: *App) void {
    const log = app.log orelse return;
    const items = app.eng.outbox.items;
    if (items.len == 0) return;
    const e = items[items.len - 1];
    if (e.body.len > 4096) return;
    if (e.ents_tail.len > envelope.max_text_tail) return;
    var buf: [3 + 16 + 8 + 16 + 2 + 4096 + envelope.max_text_tail]u8 = undefined;
    std.mem.writeInt(u16, buf[1..3], @intCast(e.cid), .little);
    buf[0] = 1;
    @memcpy(buf[3 .. 3 + 16], &e.msg_id);
    std.mem.writeInt(u64, buf[19..27], e.ts_ms, .little);
    const body_off: usize = if (e.reply_to) |rid| blk: {
        buf[0] |= 0b100;
        @memcpy(buf[29..45], &rid);
        break :blk 45;
    } else 29;
    std.mem.writeInt(u16, buf[body_off - 2 ..][0..2], @intCast(e.body.len), .little);
    @memcpy(buf[body_off .. body_off + e.body.len], e.body);
    var n = body_off + e.body.len;
    // хвост entities: пусто -> счётчик 0 (новые записи всегда с хвостом)
    if (e.ents_tail.len == 0) {
        buf[n] = 0;
        n += 1;
    } else {
        @memcpy(buf[n .. n + e.ents_tail.len], e.ents_tail);
        n += e.ents_tail.len;
    }
    _ = log.append(.outbox, buf[0..n]) catch {};
}

/// Записать в лог погашение (ACK) записи outbox — заодно это отметка
/// delivered для истории: при загрузке ACK-записи ставят бит1 записям
/// kind msg (рассинхрон «доставлено, но в истории 0» после рестарта).
/// Кэш истории гасится сразу. Вызывается ПОД app.mu. Запись НЕ ставится
/// в очередь синхронизации (применённая с устройства — иначе петля).
fn persistOutboxAck(app: *App, cid: i64, msg_id: [16]u8) void {
    writeOutboxAck(app, cid, msg_id);
    // доставленность реплицируется: бит delivered в истории другого
    // устройства должен погаситься тем же ACK-ом
    var buf: [3 + 16]u8 = undefined;
    buf[0] = 0;
    std.mem.writeInt(u16, buf[1..3], @intCast(cid), .little);
    @memcpy(buf[3 .. 3 + 16], &msg_id);
    syncEnqueue(app, @backingInt(sync_mod.RecKind.ack), &buf);
    syncPumpLocked(app);
}

/// Чистая запись ACK в лог (без постановки в очередь синхронизации):
/// локальный ACK доставки и путь применения синхронизации.
fn writeOutboxAck(app: *App, cid: i64, msg_id: [16]u8) void {
    var buf: [3 + 16]u8 = undefined;
    buf[0] = 0;
    std.mem.writeInt(u16, buf[1..3], @intCast(cid), .little);
    @memcpy(buf[3 .. 3 + 16], &msg_id);
    if (app.log) |log| _ = log.append(.outbox, &buf) catch {};
    histDelivered(app, msg_id);
}

/// Записать реакцию в лог (kind react: [cid u16][flags u8][msg_id 16]
/// [op u8][code u32][ts u64]; бит0 flags = моя реакция).
fn persistReact(app: *App, cid: i64, mine: bool, msg_id: [16]u8, op: u8, code: u32, ts_ms: i64) void {
    const log = app.log orelse return;
    var buf: [32]u8 = undefined;
    std.mem.writeInt(u16, buf[0..2], @intCast(cid), .little);
    buf[2] = @intFromBool(mine);
    @memcpy(buf[3 .. 3 + 16], &msg_id);
    buf[19] = op;
    std.mem.writeInt(u32, buf[20..24], code, .little);
    std.mem.writeInt(u64, buf[24..32], @intCast(ts_ms), .little);
    _ = log.append(.react, buf[0..32]) catch {};
    syncEnqueue(app, @backingInt(sync_mod.RecKind.react), buf[0..32]);
    syncPumpLocked(app);
}

/// Заглушка хвоста entities «форматирования нет»: один байт счётчика 0.
const zero_tail = [_]u8{0};

/// Message-log body offset. Bit2 in flags marks a reply record and inserts
/// `reply_to[16]` before `[body_len u16][body]`; bit2 was unused in v1.
fn msgBodyOffset(rec: []const u8) ?usize {
    if (rec.len < 29) return null;
    return if ((rec[2] & 0b100) != 0) 45 else 29;
}

fn msgBodyLen(rec: []const u8) ?usize {
    const off = msgBodyOffset(rec) orelse return null;
    if (rec.len < off) return null;
    return std.mem.readInt(u16, rec[off - 2 ..][0..2], .little);
}

fn msgReplyTo(rec: []const u8) ?[16]u8 {
    if (rec.len < 45 or (rec[2] & 0b100) == 0) return null;
    return rec[29..45].*;
}

/// Хвост entities записи kind msg/outbox. Старые записи без reply остаются
/// читаемыми; битый хвост — null: запись пропускается.
fn recEntityTail(rec: []const u8, blen: usize) ?[]const u8 {
    const body_off = msgBodyOffset(rec) orelse return null;
    const body_end = body_off + blen;
    if (rec.len == body_end) return &zero_tail;
    if (rec.len < body_end) return null;
    const tail = rec[body_end..];
    _ = envelope.parseEntities(tail, blen, null) catch return null;
    return tail;
}

/// Записать сообщение в историю (kind msg, шифрованный лог). После body —
/// хвост entities (канонический формат; пустые ents -> счётчик 0). Чтение
/// толерантно к старым записям без хвоста (история переживает апгрейд).
/// ts — реальное локальное время (мс), метка в конверте остаётся приватной.
/// Запись попадает и в лог, и в кэш истории (GET_HISTORY/GET_MESSAGE/SEARCH
/// читают только кэш). Вызывается ПОД app.mu.
fn persistMsg(app: *App, cid: i64, mine: bool, msg_id: [16]u8, reply_to: ?[16]u8, delivered: bool, ts_ms: i64, body: []const u8, ents: []const envelope.TextEntity) void {
    if (body.len == 0 or body.len > 4096) return;
    var tail_buf: [envelope.max_text_tail]u8 = undefined;
    const tail = envelope.encodeEntitiesTail(&tail_buf, ents, body.len) catch return;
    var buf: [3 + 16 + 8 + 16 + 2 + 4096 + envelope.max_text_tail]u8 = undefined;
    std.mem.writeInt(u16, buf[0..2], @intCast(cid), .little);
    // бит0 = mine, бит1 = delivered (мой текст: 0 до ACK — погашение
    // пишется записью kind outbox в persistOutboxAck)
    const reply_flag: u8 = if (reply_to != null) 0b100 else 0;
    buf[2] = @as(u8, @intFromBool(mine)) | (@as(u8, @intFromBool(delivered)) << 1) | reply_flag;
    @memcpy(buf[3 .. 3 + 16], &msg_id);
    std.mem.writeInt(u64, buf[19..27], @intCast(ts_ms), .little);
    const body_off: usize = if (reply_to) |rid| blk: {
        @memcpy(buf[29..45], &rid);
        break :blk 45;
    } else 29;
    std.mem.writeInt(u16, buf[body_off - 2 ..][0..2], @intCast(body.len), .little);
    @memcpy(buf[body_off .. body_off + body.len], body);
    @memcpy(buf[body_off + body.len ..][0..tail.len], tail);
    const rec = buf[0 .. body_off + body.len + tail.len];
    if (app.log) |log| _ = log.append(.msg, rec) catch {};
    histAppend(app, rec, msg_id);
    syncEnqueue(app, @backingInt(sync_mod.RecKind.msg), rec);
    syncPumpLocked(app);
}

/// Положить копию записи kind msg в кэш истории (+ индекс по msg_id).
/// Вызывается ПОД app.mu.
fn histAppend(app: *App, rec: []const u8, msg_id: [16]u8) void {
    const copy = app.alloc.dupe(u8, rec) catch return;
    app.hist.append(app.alloc, copy) catch {
        app.alloc.free(copy);
        return;
    };
    app.hist_idx.put(app.alloc, msg_id, app.hist.items.len - 1) catch {};
}

/// Погасить delivered в кэше истории (ACK дошёл). Вызывается ПОД app.mu.
fn histDelivered(app: *App, msg_id: [16]u8) void {
    const i = app.hist_idx.get(msg_id) orelse return;
    const rec = app.hist.items[i];
    if (rec.len >= 3) rec[2] |= 0b10; // бит1 = delivered
}

/// Выкинуть из кэша истории все записи чата (DELETE_CHAT). Полная
/// перекомпоновка: индексы msg_id смещаются. Вызывается ПОД app.mu.
fn histPurgeFor(app: *App, cid: i64) void {
    var keep: std.ArrayListUnmanaged([]u8) = .empty;
    for (app.hist.items) |rec| {
        if (rec.len >= 2 and std.mem.readInt(u16, rec[0..2], .little) == cid) {
            app.alloc.free(rec);
        } else {
            keep.append(app.alloc, rec) catch {
                // OOM: запись теряем — лучше потерять кэш-строку, чем упасть
                app.alloc.free(rec);
            };
        }
    }
    app.hist.deinit(app.alloc);
    app.hist = keep;
    app.hist_idx.clearRetainingCapacity();
    for (app.hist.items, 0..) |rec, i| {
        if (rec.len < 29) continue;
        app.hist_idx.put(app.alloc, rec[3 .. 3 + 16].*, i) catch {};
    }
}

/// Записать принятый файл в лог (kind file): переживает рестарты.
/// Вызывается под app.mu.
fn persistFileMeta(app: *App, cid: i64, file_id: [16]u8, size: u32, name: []const u8) void {
    const log = app.log orelse return;
    var buf: [23 + 64]u8 = undefined;
    std.mem.writeInt(u16, buf[0..2], @intCast(cid), .little);
    @memcpy(buf[2..18], &file_id);
    std.mem.writeInt(u32, buf[18..22], size, .little);
    const n = @min(name.len, 64);
    buf[22] = @intCast(n);
    @memcpy(buf[23 .. 23 + n], name[0..n]);
    _ = log.append(.file, buf[0 .. 23 + n]) catch {};
    syncEnqueue(app, @backingInt(sync_mod.RecKind.file), buf[0 .. 23 + n]);
    syncPumpLocked(app);
}

/// SET_NAME: payload [name str16 1..32]. Ответ пуст.
fn apiSetName(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    _ = w;
    var r = api.Reader.init(payload);
    const name = r.readStr16() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    if (name.len == 0 or name.len > invite_mod.max_name) return .BAD_ARGS;
    app.lock();
    defer app.unlock();
    app.eng.setMyProfile(name, app.eng.my_avatar_id);
    if (app.log) |log| {
        var nb: [33]u8 = undefined;
        nb[0] = 2;
        @memcpy(nb[1 .. 1 + name.len], name);
        _ = log.append(.set, nb[0 .. 1 + name.len]) catch {};
    }
    for (app.eng.contacts.items, 0..) |_, i| {
        const cid: i64 = @intCast(i + 1);
        if (app.eng.sessions.contains(cid)) {
            app.eng.sendProfile(cid) catch {};
        }
    }
    return .OK;
}

/// SET_AVATAR: payload [data str32 1..16000] — байты картинки inline.
/// Ответ: [avatar_id 16][size u32].
fn apiSetAvatar(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const bytes = r.readStr32() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    if (bytes.len == 0 or bytes.len > envelope.max_avatar_data) return .TOO_BIG;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const id = digest[0..16].*;
    {
        app.lock();
        defer app.unlock();
        if (!app.avatars.contains(id)) {
            const copy = app.alloc.dupe(u8, bytes) catch return .INTERNAL;
            app.avatars.put(app.alloc, id, copy) catch {
                app.alloc.free(copy);
                return .INTERNAL;
            };
        }
        app.eng.setMyProfile(app.eng.myName(), id);
        if (app.log) |log| {
            var rb: [17]u8 = undefined;
            rb[0] = 1;
            @memcpy(rb[1..17], &id);
            _ = log.append(.set, rb[0..17]) catch {};
        }
        // кэш байтов — тоже kind avatar, чтобы peer-REQ перекачивал и после рестарта
        if (app.log) |log| {
            var ab: [18 + 16000]u8 = undefined;
            @memcpy(ab[0..16], &id);
            std.mem.writeInt(u16, ab[16..18], @intCast(bytes.len), .little);
            @memcpy(ab[18 .. 18 + bytes.len], bytes);
            _ = log.append(.avatar, ab[0 .. 18 + bytes.len]) catch {};
        }
        // PROFILE всем онлайн-сессиям
        for (app.eng.contacts.items, 0..) |_, i| {
            const cid: i64 = @intCast(i + 1);
            if (app.eng.sessions.contains(cid)) {
                app.eng.sendProfile(cid) catch {};
            }
        }
    }
    w.putBytes(&id) catch return .INTERNAL;
    w.putU32(@intCast(bytes.len)) catch return .INTERNAL;
    return .OK;
}

/// GET_MY_AVATAR: empty payload; response [avatar_id 16][data str16].
/// Reads the same encrypted-log-backed cache used for peer AVATAR_REQ.
fn apiGetMyAvatar(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    if (payload.len != 0) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    const id = app.eng.my_avatar_id;
    if (std.mem.eql(u8, &id, &@as([16]u8, @splat(0)))) return .NOT_FOUND;
    const data = app.avatars.get(id) orelse return .NOT_FOUND;
    w.putBytes(&id) catch return .INTERNAL;
    w.putStr16(data) catch return .INTERNAL;
    return .OK;
}

/// CREATE_RECOVERY_BACKUP (41): payload [unlock_secret 32] → [backup str32].
/// Запечатывает сид+профиль+контакты (БЕЗ истории) ключом из секрета GUI
/// (passkey PRF / recovery-код); блоб GUI хранит в пользовательском
/// облаке. Секрет по UDS (0700-сокет на машине пользователя) передаётся
/// один раз и ядром не сохраняется. Nonce — до лока (io вне спин-лока).
fn apiCreateRecoveryBackup(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const secret = r.readBytes(recovery_codec.secret_length) catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    var nonce: [recovery_codec.nonce_length]u8 = undefined;
    app.io.random(&nonce);
    app.lock();
    defer app.unlock();
    const res = recovery_mod.createBackup(app, secret[0..recovery_codec.secret_length], nonce);
    const blob = switch (res) {
        .ok => |b| b,
        .err => |st| return st,
    };
    defer app.alloc.free(blob);
    w.putStr32(blob) catch return .INTERNAL;
    return .OK;
}

/// RESTORE_RECOVERY_BACKUP (42): payload [backup str32][unlock_secret 32]
/// → [bundle 64][fingerprint 32][name str16]. Только пустой профиль
/// (демон без сида); битый пакет или чужой секрет — BAD_RECOVERY. После
/// успеха профиль провижен, сетевые потоки поднимаются сами (main loop).
fn apiRestoreRecoveryBackup(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const blob = r.readStr32() catch return .BAD_FRAME;
    const secret = r.readBytes(recovery_codec.secret_length) catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    if (blob.len == 0) return .BAD_ARGS;
    var backup = recovery_codec.open(app.alloc, blob, secret[0..recovery_codec.secret_length]) catch |e| switch (e) {
        error.BadFormat, error.Tampered, error.TooBig => return .BAD_RECOVERY,
        error.OutOfMemory => return .INTERNAL,
    };
    defer backup.deinit(app.alloc);
    app.lock();
    defer app.unlock();
    recovery_mod.applyBackup(app, &backup) catch |e| switch (e) {
        error.AlreadyProvisioned => return .ALREADY_PROVISIONED,
        error.BadRecovery => return .BAD_RECOVERY,
        error.Internal => return .INTERNAL,
    };
    // ответ — как GET_IDENTITY + имя: GUI сразу показывает восстановленный
    // профиль и сверяет отпечаток
    const bundle = app.id.bundle();
    var digest: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(&bundle, &digest, .{});
    w.putBytes(&bundle) catch return .INTERNAL;
    w.putBytes(&digest) catch return .INTERNAL;
    w.putStr16(app.eng.myName()) catch return .INTERNAL;
    return .OK;
}

/// SEND_FILE: payload [cid u32][path str16] — путь в ФС пользователя демона.
/// Ответ: [file_id 16][size u32][chunks u32].
/// Требует живой сессии (файлы не ставятся в outbox); file_id = SHA-256[0..16].
/// Передача окном tx_window_chunks с подтверждениями FILE_ACK: разрыв
/// сессии не теряет прогресс — докачка автоматически при реконнекте
/// (resumeTxFilesLocked в bindSession).
fn apiSendFile(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    const path = r.readStr16() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    if (path.len == 0) return .BAD_ARGS;
    // только имя файла, без каталогов
    const base = if (std.mem.lastIndexOfScalar(u8, path, '/')) |i| path[i + 1 ..] else path;
    if (base.len == 0 or base.len > envelope.max_file_name) return .BAD_ARGS;
    const f = std.Io.Dir.openFileAbsolute(app.io, path, .{ .mode = .read_only }) catch
        return .FILE_NOT_FOUND;
    defer f.close(app.io);
    // лимит: 64 МБ (u32 размер + разумный таймаут перекачки)
    const max_file_total = 64 * 1024 * 1024;
    const data = app.alloc.alloc(u8, max_file_total) catch return .INTERNAL;
    defer app.alloc.free(data);
    const n = f.readPositionalAll(app.io, data, 0) catch return .FILE_NOT_FOUND;
    if (n == 0 or n > std.math.maxInt(u32)) return .TOO_BIG;
    const bytes = data[0..n];
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const file_id = digest[0..16].*;
    const total: u32 = @intCast(@divTrunc(n + envelope.max_file_chunk - 1, envelope.max_file_chunk));
    {
        app.lock();
        defer app.unlock();
        if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
        // движок владеет передачей (окно, докачка FILE_ACK, память до
        // подтверждения); без сессии файл стоит в очереди как TEXT-outbox
        const outcome = app.eng.sendFile(@intCast(cid), file_id, base, bytes, digest) catch |e| {
            return statusOf(e);
        };
        _ = outcome;
    }
    w.putBytes(&file_id) catch return .INTERNAL;
    w.putU32(@intCast(n)) catch return .INTERNAL;
    w.putU32(total) catch return .INTERNAL;
    return .OK;
}

/// GET_AVATAR_ID: payload [cid u32]. Ответ: [avatar_id 16] (нули — аватара нет).
fn apiGetAvatarId(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
    const c = &app.eng.contacts.items[cid - 1];
    w.putBytes(&c.avatar_id) catch return .INTERNAL;
    return .OK;
}

/// GET_HISTORY: payload [cid u32][limit u32] (0 → 50, максимум 200).
/// Ответ: [total u32][count u32] × {[flags u8 bit0 mine bit1 delivered]
/// [msg_id 16][ts_ms u64][body str16][ent_count u8] × {entity}} — записи
/// старые → новые. Окно режется и бюджетом payload (≤ 16 МиБ): count может
/// быть меньше limit для entity-тяжёлой истории. bit1 delivered ставится
/// только ACK-ом (не фактом записи в сокет). Источние данных — кэш
/// истории в памяти (лог читается один раз при старте).
fn apiGetHistory(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    var limit = r.readU32() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    if (limit == 0) limit = 50;
    if (limit > 200) return .TOO_BIG;
    // под локом: кэш истории живут мутации (persist/ACK/DELETE_CHAT)
    app.lock();
    defer app.unlock();
    if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
    if (app.eng.contacts.items[cid - 1].deleted) return .NO_CONTACT;
    // записи: [cid u16][flags u8][msg_id 16][ts u64][len u16][body][ents]
    const recs = app.hist.items;
    var total: usize = 0;
    var start: usize = recs.len; // индекс первой записи окна
    {
        var count: usize = 0;
        var budget: usize = 8; // total u32 + count u32
        var i: usize = recs.len;
        while (i > 0) {
            i -= 1;
            const rec = recs[i];
            if (rec.len < 29) continue;
            if (std.mem.readInt(u16, rec[0..2], .little) != cid) continue;
            const body_off = msgBodyOffset(rec) orelse continue;
            const blen = msgBodyLen(rec) orelse continue;
            if (rec.len < body_off + blen) continue;
            const tail = recEntityTail(rec, blen) orelse continue;
            total += 1;
            count += 1;
            budget += 1 + 16 + 8 + 2 + blen + tail.len;
            if (count == limit or budget > api.max_payload) {
                start = i;
                break;
            }
        }
        if (i == 0 and start == recs.len) start = 0;
    }
    // две фазы: посчитать записи окна, потом записать (payload один кадр);
    // фильтры идентичны фазе 1 — записей ровно in_window, бюджет уже учтён
    var in_window: usize = 0;
    var idx2 = start;
    while (idx2 < recs.len) : (idx2 += 1) {
        const rec = recs[idx2];
        if (rec.len < 29) continue;
        if (std.mem.readInt(u16, rec[0..2], .little) != cid) continue;
        const body_off = msgBodyOffset(rec) orelse continue;
        const blen = msgBodyLen(rec) orelse continue;
        if (rec.len < body_off + blen) continue;
        if (recEntityTail(rec, blen) == null) continue;
        in_window += 1;
    }
    w.putU32(@intCast(total)) catch return .INTERNAL;
    w.putU32(@intCast(in_window)) catch return .INTERNAL;
    idx2 = start;
    while (idx2 < recs.len) : (idx2 += 1) {
        const rec = recs[idx2];
        if (rec.len < 29) continue;
        if (std.mem.readInt(u16, rec[0..2], .little) != cid) continue;
        const flags = rec[2];
        const msg_id: [16]u8 = rec[3 .. 3 + 16].*;
        const ts_ms = std.mem.readInt(u64, rec[19..27], .little);
        const body_off = msgBodyOffset(rec) orelse continue;
        const blen = msgBodyLen(rec) orelse continue;
        if (rec.len < body_off + blen) continue;
        const tail = recEntityTail(rec, blen) orelse continue;
        w.putU8(flags) catch return .INTERNAL;
        w.putBytes(&msg_id) catch return .INTERNAL;
        w.putU64(ts_ms) catch return .INTERNAL;
        w.putStr16(rec[body_off .. body_off + blen]) catch return .INTERNAL;
        w.putBytes(tail) catch return .INTERNAL;
    }
    return .OK;
}

/// GET_MESSAGE: payload [msg_id 16]. Ответ:
/// [cid u32][flags u8 bit0 mine bit1 delivered][ts_ms u64][body str16]
/// [ent_count u8] × {entity}
/// [react_count u32] × {[flags u8 bit0 mine][codepoint u32][ts_ms u64]}.
/// Нет записи — NOT_FOUND.
/// GET_CONTACT_STATE (43): [cid u32] → [state u8][attempt u32]
/// [last_error u16][next_retry_ms u32]. Дешёвый опрос стадии подключения
/// вместо полных LIST_CONTACTS/событий. next_retry_ms — остаток до
/// автодозвона (0 — повтора нет/уже пора).
fn apiGetContactState(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
    const state: api.ConnState = connStateOfLocked(app, @intCast(cid));
    const e = app.conn_st.get(@intCast(cid)) orelse ConnEntry{};
    w.putU8(@backingInt(state)) catch return .INTERNAL;
    w.putU32(e.attempt) catch return .INTERNAL;
    w.putU16(e.last_error) catch return .INTERNAL;
    w.putU32(retryRemainingMs(e.next_retry_at, app.nowMs())) catch return .INTERNAL;
    return .OK;
}

/// SUBSCRIBE_CONTACT_UPDATES (45): ∅ → [epoch 16][revision u64].
/// На этом конне включаются события CONTACT_STATE_CHANGED /
/// CONTACTS_CHANGED / CONTACT_UPSERTED. Идемпотентно: повторная подписка
/// обновляет revision-точку. Остальные события конну не отправляются.
fn apiSubscribeContactUpdates(app: *App, conn: *api_srv.Conn, payload: []const u8, w: *api.Writer) api.Status {
    if (payload.len != 0) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    conn.subscribed = true;
    w.putBytes(&app.contacts_epoch) catch return .INTERNAL;
    w.putU64(app.contacts_rev) catch return .INTERNAL;
    return .OK;
}

/// GET_BOOTSTRAP (46): ∅ → [api_version 3×u16][epoch 16][revision u64]
/// [count u32] × ContactView. Один вызов вместо каскада GET_CONTACTS +
/// GET_CONTACT_STATE: стартовая отрисовка списка. Порядок — порядку
/// слотов движка (стабилен внутри запуска). TOO_BIG — контактов больше
/// bootstrap_max_contacts: клиент обязан идти через GET_CONTACTS +
/// GET_CONTACTS_DELTA.
fn apiGetBootstrap(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    if (payload.len != 0) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    if (!app.provisioned) return .NOT_INITIALIZED;
    // фаза 1: счёт (бюджет кадра)
    var count: usize = 0;
    var budget: usize = 6 + 16 + 8 + 4;
    for (app.eng.contacts.items) |*c| {
        if (c.deleted) continue;
        count += 1;
        budget += contact_view_size + 32;
        if (count >= bootstrap_max_contacts) return .TOO_BIG;
        if (budget > api.max_payload) return .TOO_BIG;
    }
    w.putU16(api.api_version[0]) catch return .INTERNAL;
    w.putU16(api.api_version[1]) catch return .INTERNAL;
    w.putU16(api.api_version[2]) catch return .INTERNAL;
    w.putBytes(&app.contacts_epoch) catch return .INTERNAL;
    w.putU64(app.contacts_rev) catch return .INTERNAL;
    w.putU32(@intCast(count)) catch return .INTERNAL;
    // фаза 2: записи (мутаций под локом нет — размер совпадает)
    for (app.eng.contacts.items, 0..) |*c, i| {
        if (c.deleted) continue;
        putContactViewLocked(app, w, @intCast(i + 1)) catch return .INTERNAL;
    }
    return .OK;
}

/// GET_CONTACTS_DELTA (47): [epoch 16][from_rev u64] → [epoch 16]
/// [to_rev u64][count u32] × {[rev u64][kind u8][cid u32](+view)}.
/// Воспроизведение кольца ревизий: клиент ведёт (epoch, rev) и
/// докачивает пропущенное. RESYNC_REQUIRED — чужой epoch или rev вне
/// окна кольца: полный пересинхрон (GET_BOOTSTRAP/GET_CONTACTS).
fn apiGetContactsDelta(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const epoch = r.readBytes(16) catch return .BAD_FRAME;
    const from_rev = r.readU64() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    if (!app.provisioned) return .NOT_INITIALIZED;
    if (!std.mem.eql(u8, epoch, &app.contacts_epoch)) return .RESYNC_REQUIRED;
    if (from_rev > app.contacts_rev) return .BAD_ARGS;
    // окно кольца: доступная история ревизий
    if (app.contacts_rev == 0 or from_rev == app.contacts_rev) {
        // пустая дельта — валидный ответ (пусто)
        w.putBytes(&app.contacts_epoch) catch return .INTERNAL;
        w.putU64(app.contacts_rev) catch return .INTERNAL;
        w.putU32(0) catch return .INTERNAL;
        return .OK;
    }
    const oldest: u64 = if (app.contacts_ring_len < contact_ring_cap)
        app.contacts_rev - app.contacts_ring_len + 1
    else
        app.contacts_ring[app.contacts_ring_pos].rev;
    if (from_rev + 1 < oldest) return .RESYNC_REQUIRED;
    // фаза 1: сбор индексов записей (rev > from_rev, ревизии плотные)
    const span: usize = @intCast(app.contacts_rev - from_rev);
    if (span > contact_ring_cap) return .RESYNC_REQUIRED;
    var budget: usize = 16 + 8 + 4 + span * (8 + 1 + 4);
    var iter: usize = 0;
    while (iter < span) : (iter += 1) {
        const idx = (app.contacts_ring_pos + contact_ring_cap - span + iter) % contact_ring_cap;
        const ch = app.contacts_ring[idx];
        if (ch.kind == @backingInt(api.DeltaChange.upsert)) budget += contact_view_size + 32;
    }
    if (budget > api.max_payload) return .TOO_BIG;
    w.putBytes(&app.contacts_epoch) catch return .INTERNAL;
    w.putU64(app.contacts_rev) catch return .INTERNAL;
    w.putU32(@intCast(span)) catch return .INTERNAL;
    // фаза 2: записи (порядок возрастания rev)
    iter = 0;
    while (iter < span) : (iter += 1) {
        const idx = (app.contacts_ring_pos + contact_ring_cap - span + iter) % contact_ring_cap;
        const ch = app.contacts_ring[idx];
        w.putU64(ch.rev) catch return .INTERNAL;
        w.putU8(ch.kind) catch return .INTERNAL;
        w.putU32(@intCast(ch.cid)) catch return .INTERNAL;
        if (ch.kind == @backingInt(api.DeltaChange.upsert)) {
            // view на ТЕКУЩИЙ момент: применение клиентом идемпотентно
            putContactViewLocked(app, w, ch.cid) catch return .INTERNAL;
        }
    }
    return .OK;
}

/// GET_REACHABLE_ENDPOINTS (48): ∅ → [count u8] × [address str16] —
/// "ip:port" прямых адресов, по которым нас можно найти в LAN (для QR
/// прямого приглашения без multicast-поиска). Пусто — не слушаем или
/// включён use_tor_mask (прямой адрес раскрыть нельзя).
fn apiGetReachableEndpoints(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    if (payload.len != 0) return .BAD_FRAME;
    app.lock();
    const listening = app.listening;
    const port = app.listen_port;
    const tor = app.cfg.use_tor_mask;
    app.unlock();
    if (!listening or tor) {
        w.putU8(0) catch return .INTERNAL;
        return .OK;
    }
    // перечисление интерфейсов — системные вызовы, БЕЗ app.mu
    var ips: [endpoints_mod.max_endpoints][4]u8 = undefined;
    const n = endpoints_mod.enumerateLocalV4(&ips) catch |e| switch (e) {
        error.Network => {
            // перечисление недоступно: пустой список, не ошибка
            w.putU8(0) catch return .INTERNAL;
            return .OK;
        },
    };
    w.putU8(@intCast(n)) catch return .INTERNAL;
    for (ips[0..n]) |ip| {
        var hbuf: [endpoints_mod.host_max]u8 = undefined;
        var ab: [endpoints_mod.host_max + 8]u8 = undefined;
        const host = endpoints_mod.fmtHost(&hbuf, ip);
        const addr = std.fmt.bufPrint(&ab, "{s}:{d}", .{ host, port }) catch return .INTERNAL;
        w.putStr16(addr) catch return .INTERNAL;
    }
    return .OK;
}

/// CREATE_INVITE_EX (49): [mode u8][name str16][direct str16][relay str16]
/// → [code str16][invite_id 16]. mode: 0 discovery / 1 direct / 2 relay_only /
/// 3 direct_then_relay (i3-код: прямой адрес + relay-fallback в одном).
/// direct/relay — "host:port". use_tor_mask + прямой режим — BAD_ARGS
/// (свой IP не раскрываем; relay_only остаётся доступен).
/// invite_id — НЕсекретный идентикатор для GET_INVITE_STATE.
fn apiCreateInviteEx(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const mode_in = r.readU8() catch return .BAD_FRAME;
    const mode = std.enums.fromInt(api.InviteExMode, mode_in) orelse return .BAD_ARGS;
    const name_in = r.readStr16() catch return .BAD_FRAME;
    const direct_in = r.readStr16() catch return .BAD_FRAME;
    const relay_in = r.readStr16() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    if (name_in.len > invite_mod.max_name) return .BAD_ARGS;
    if (direct_in.len > invite_mod.v3_addr_max or relay_in.len > invite_mod.v3_addr_max) return .BAD_ARGS;
    const d: ?[]const u8 = if (direct_in.len > 0) direct_in else null;
    const rl: ?[]const u8 = if (relay_in.len > 0) relay_in else null;
    switch (mode) {
        .discovery => {
            if (d != null or rl != null) return .BAD_ARGS;
        },
        .direct => {
            if (d == null or rl != null) return .BAD_ARGS;
        },
        .relay_only => {
            if (rl == null or d != null) return .BAD_ARGS;
        },
        .direct_then_relay => {
            if (d == null or rl == null) return .BAD_ARGS;
        },
    }
    const name: []const u8 = if (name_in.len == 0) "stille-messenger" else name_in;
    var secret: [invite_mod.secret_len]u8 = undefined;
    app.io.random(&secret);
    defer std.crypto.secureZero(u8, &secret);
    var invite_id: [16]u8 = undefined;
    app.io.random(&invite_id);
    {
        app.lock();
        defer app.unlock();
        if (mode == .direct or mode == .direct_then_relay) {
            if (app.cfg.use_tor_mask) return .BAD_ARGS; // прямой адрес не раскрываем
        }
        var slot: ?usize = null;
        for (&app.invites, 0..) |*reg, i| {
            if (reg.used or reg.created_ms == 0) {
                slot = i;
                break;
            }
        }
        const i = slot orelse return .TOO_MANY_INVITES;
        app.invites[i] = .{ .secret = secret, .created_ms = app.nowMs(), .used = false, .invite_id = invite_id };
        if (rl) |ra| {
            const n = @min(ra.len, relay_addr_max);
            @memcpy(app.invites[i].relay_buf[0..n], ra[0..n]);
            app.invites[i].relay_len = @intCast(n);
        }
    }
    // код: гибрид — v3 (i3), одиночные — v2 (обратная совместимость)
    var out: [512]u8 = undefined;
    var rbuf: [80]u8 = undefined;
    const code: []const u8 = blk: {
        switch (mode) {
            .direct_then_relay => break :blk invite_mod.encode3(&out, app.id.bundle(), secret, name, d, rl) catch return .BAD_ARGS,
            .relay_only => {
                const s = std.fmt.bufPrint(&rbuf, "r/{s}", .{rl.?}) catch return .BAD_ARGS;
                break :blk invite_mod.encode2(&out, app.id.bundle(), secret, name, s) catch return .BAD_ARGS;
            },
            .direct => break :blk invite_mod.encode2(&out, app.id.bundle(), secret, name, d) catch return .BAD_ARGS,
            .discovery => break :blk invite_mod.encode2(&out, app.id.bundle(), secret, name, null) catch return .BAD_ARGS,
        }
    };
    w.putStr16(code) catch return .INTERNAL;
    w.putBytes(&invite_id) catch return .INTERNAL;
    if (rl) |ra| {
        const addr_copy = app.alloc.dupe(u8, ra) catch return .INTERNAL;
        if (std.Thread.spawn(.{}, relayLinkerLoop, .{ app, secret, addr_copy })) |t| {
            t.detach();
        } else |_| {
            app.alloc.free(addr_copy);
        }
    }
    return .OK;
}

/// GET_INVITE_STATE (50): [invite_id 16] → [state u8][accepted_cid u32]
/// [expires_at_ms i64]. Активные приглашения — из таблицы регистрации;
/// погашенные (consumed/failed) — кольцо диагностики на invite_done_cap
/// записей, дальше NOT_FOUND (клиент обязан держать последний ответ сам).
/// expires_at_ms — 0 (lifetime приглашения управляется владением кода).
fn apiGetInviteState(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const invite_id = r.readBytes(16) catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    // живая регистрация
    for (&app.invites) |*reg| {
        if (reg.created_ms == 0) continue;
        if (!std.mem.eql(u8, &reg.invite_id, invite_id)) continue;
        if (reg.used) continue;
        const st: api.InviteState = if (reg.joining) .joining else .active;
        w.putU8(@backingInt(st)) catch return .INTERNAL;
        w.putU32(0) catch return .INTERNAL;
        w.putI64(0) catch return .INTERNAL;
        return .OK;
    }
    // кольцо завершённых (свежее поверх старого)
    var i: usize = app.invite_done_len;
    while (i > 0) {
        i -= 1;
        const idx = (app.invite_done_pos + invite_done_cap - 1 - i) % invite_done_cap;
        const done = app.invite_done[idx];
        if (!std.mem.eql(u8, &done.invite_id, invite_id)) continue;
        w.putU8(done.state) catch return .INTERNAL;
        w.putU32(done.accepted_cid) catch return .INTERNAL;
        w.putI64(0) catch return .INTERNAL;
        return .OK;
    }
    return .NOT_FOUND;
}

/// GET_HISTORY_PAGE (51): [cid u32][has_cursor u8][before_ts u64]
/// [before_msg_id 16][limit u16] → [has_more u8][next_ts u64]
/// [next_msg_id 16][count u32] × records (формат записей — как
/// GET_HISTORY). Строгий порядок (ts, msg_id): пагинация курсором —
/// экстремально дешёвая (никаких окон) и стабильная при удалении
/// старых записей: граница — не позиция, а кортеж.
fn apiGetHistoryPage(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    const has_cursor = r.readU8() catch return .BAD_FRAME;
    const before_ts = r.readU64() catch return .BAD_FRAME;
    const before_msg_id = r.readBytes(16) catch return .BAD_FRAME;
    var limit = r.readU16() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    if (limit == 0) limit = 30;
    if (limit > 200) return .TOO_BIG;
    app.lock();
    defer app.unlock();
    if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
    if (app.eng.contacts.items[cid - 1].deleted) return .NO_CONTACT;

    // фаза 1: собрать валидные записи чата в буфер индексов, отсортировать
    // по строгому порядку (ts, msg_id) — устойчивая пагинация при равных ts
    const RecIdx = struct { ts: u64, msg_id: [16]u8, rec: usize };
    var recs_idx = std.ArrayListUnmanaged(RecIdx).empty;
    defer recs_idx.deinit(app.alloc);
    const all = app.hist.items;
    for (all, 0..) |rec, i| {
        if (rec.len < 29) continue;
        if (std.mem.readInt(u16, rec[0..2], .little) != cid) continue;
        const body_off = msgBodyOffset(rec) orelse continue;
        const blen = msgBodyLen(rec) orelse continue;
        if (rec.len < body_off + blen) continue;
        if (recEntityTail(rec, blen) == null) continue;
        recs_idx.append(app.alloc, .{
            .ts = std.mem.readInt(u64, rec[19..27], .little),
            .msg_id = rec[3 .. 3 + 16].*,
            .rec = i,
        }) catch return .INTERNAL;
    }
    const ctx = struct {
        fn lt(_: void, a: RecIdx, b: RecIdx) bool {
            if (a.ts != b.ts) return a.ts < b.ts;
            return std.mem.order(u8, &a.msg_id, &b.msg_id) == .lt;
        }
    };
    std.mem.sort(RecIdx, recs_idx.items, {}, ctx.lt);
    // Страница выдаётся от новых записей к старым. Курсор исключает
    // самую старую запись предыдущей страницы и всё, что новее неё.
    var end: usize = recs_idx.items.len;
    if (has_cursor != 0) {
        end = 0;
        while (end < recs_idx.items.len) {
            const it = recs_idx.items[end];
            const before = it.ts < before_ts or
                (it.ts == before_ts and std.mem.order(u8, &it.msg_id, before_msg_id) == .lt);
            if (!before) break;
            end += 1;
        }
    }
    var start: usize = 0;
    if (end > limit) start = end - limit;
    const has_more = start > 0;
    // Курсор следующей страницы: самая старая выданная запись.
    var next_ts: u64 = 0;
    var next_msg_id: [16]u8 = @splat(0);
    if (start < end) {
        next_ts = recs_idx.items[start].ts;
        next_msg_id = recs_idx.items[start].msg_id;
    }
    // фаза 2: бюджет и запись (записи — как GET_HISTORY)
    var budget: usize = 1 + 8 + 16 + 4;
    var i: usize = start;
    while (i < end) : (i += 1) {
        const rec = all[recs_idx.items[i].rec];
        const blen = msgBodyLen(rec).?;
        const tail = recEntityTail(rec, blen).?;
        budget += 1 + 16 + 8 + 2 + blen + tail.len;
    }
    if (budget > api.max_payload) return .TOO_BIG;
    w.putU8(@intFromBool(has_more)) catch return .INTERNAL;
    w.putU64(next_ts) catch return .INTERNAL;
    w.putBytes(&next_msg_id) catch return .INTERNAL;
    w.putU32(@intCast(end - start)) catch return .INTERNAL;
    i = end;
    while (i > start) {
        i -= 1;
        const rec = all[recs_idx.items[i].rec];
        const flags = rec[2];
        const msg_id: [16]u8 = rec[3 .. 3 + 16].*;
        const ts_ms = std.mem.readInt(u64, rec[19..27], .little);
        const body_off = msgBodyOffset(rec).?;
        const blen = msgBodyLen(rec).?;
        const tail = recEntityTail(rec, blen).?;
        w.putU8(flags) catch return .INTERNAL;
        w.putBytes(&msg_id) catch return .INTERNAL;
        w.putU64(ts_ms) catch return .INTERNAL;
        w.putStr16(rec[body_off .. body_off + blen]) catch return .INTERNAL;
        w.putBytes(tail) catch return .INTERNAL;
    }
    return .OK;
}

fn apiGetMessage(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const want: [16]u8 = (r.readBytes(16) catch return .BAD_FRAME)[0..16].*;
    if (r.hasMore()) return .BAD_FRAME;
    const log = app.log orelse return .NOT_FOUND;
    // под локом: кэш истории живут мутации (persist/DELETE_CHAT)
    app.lock();
    defer app.unlock();
    const i = app.hist_idx.get(want) orelse return .NOT_FOUND;
    const rec = app.hist.items[i];
    const flags = rec[2];
    const cid = std.mem.readInt(u16, rec[0..2], .little);
    const ts_ms = std.mem.readInt(u64, rec[19..27], .little);
    const body_off = msgBodyOffset(rec) orelse return .NOT_FOUND;
    const blen = msgBodyLen(rec) orelse return .NOT_FOUND;
    const tail = recEntityTail(rec, blen) orelse return .NOT_FOUND;
    w.putU32(cid) catch return .INTERNAL;
    w.putU8(flags) catch return .INTERNAL;
    w.putU64(ts_ms) catch return .INTERNAL;
    w.putStr16(rec[body_off .. body_off + blen]) catch return .INTERNAL;
    w.putBytes(tail) catch return .INTERNAL;
    // реакции на это сообщение
    const rrecs = log.readAll(.react, app.alloc) catch return .INTERNAL;
    defer {
        for (rrecs) |rr| app.alloc.free(rr);
        app.alloc.free(rrecs);
    }
    const ReactionState = struct { flags: u8, code: u32, ts: u64 };
    var active: [3]ReactionState = undefined;
    var active_n: usize = 0;
    for (rrecs) |rr| {
        if (rr.len < 31 or !std.mem.eql(u8, rr[3 .. 3 + 16], &want)) continue;
        const op: u8 = if (rr.len >= 32) rr[19] else envelope.react_add;
        const code = if (rr.len >= 32) std.mem.readInt(u32, rr[20..24], .little) else std.mem.readInt(u32, rr[19..23], .little);
        const ts = if (rr.len >= 32) std.mem.readInt(u64, rr[24..32], .little) else std.mem.readInt(u64, rr[23..31], .little);
        var found: ?usize = null;
        for (active[0..active_n], 0..) |item, j| if (item.code == code) {
            found = j;
            break;
        };
        if (op == envelope.react_remove) {
            if (found) |j| {
                active[j] = active[active_n - 1];
                active_n -= 1;
            }
        } else if (found) |j| {
            active[j] = .{ .flags = rr[2], .code = code, .ts = ts };
        } else if (active_n < active.len) {
            active[active_n] = .{ .flags = rr[2], .code = code, .ts = ts };
            active_n += 1;
        }
    }
    w.putU32(@intCast(active_n)) catch return .INTERNAL;
    for (active[0..active_n]) |item| {
        w.putU8(item.flags) catch return .INTERNAL;
        w.putU32(item.code) catch return .INTERNAL;
        w.putU64(item.ts) catch return .INTERNAL;
    }
    return .OK;
}

/// GET_REACTIONS: payload [msg_id 16], response active reactions only.
fn apiGetReactions(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const want: [16]u8 = (r.readBytes(16) catch return .BAD_FRAME)[0..16].*;
    if (r.hasMore()) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    if (app.hist_idx.get(want) == null) return .NOT_FOUND;
    const log = app.log orelse {
        w.putU32(0) catch return .INTERNAL;
        return .OK;
    };
    const rrecs = log.readAll(.react, app.alloc) catch return .INTERNAL;
    defer {
        for (rrecs) |rr| app.alloc.free(rr);
        app.alloc.free(rrecs);
    }
    const ReactionState = struct { flags: u8, code: u32, ts: u64 };
    var active: [3]ReactionState = undefined;
    var active_n: usize = 0;
    for (rrecs) |rr| {
        if (rr.len < 31 or !std.mem.eql(u8, rr[3 .. 3 + 16], &want)) continue;
        const op: u8 = if (rr.len >= 32) rr[19] else envelope.react_add;
        const code = if (rr.len >= 32) std.mem.readInt(u32, rr[20..24], .little) else std.mem.readInt(u32, rr[19..23], .little);
        const ts = if (rr.len >= 32) std.mem.readInt(u64, rr[24..32], .little) else std.mem.readInt(u64, rr[23..31], .little);
        var found: ?usize = null;
        for (active[0..active_n], 0..) |item, j| if (item.code == code) {
            found = j;
            break;
        };
        if (op == envelope.react_remove) {
            if (found) |j| {
                active[j] = active[active_n - 1];
                active_n -= 1;
            }
        } else if (found) |j| {
            active[j] = .{ .flags = rr[2], .code = code, .ts = ts };
        } else if (active_n < active.len) {
            active[active_n] = .{ .flags = rr[2], .code = code, .ts = ts };
            active_n += 1;
        }
    }
    w.putU32(@intCast(active_n)) catch return .INTERNAL;
    for (active[0..active_n]) |item| {
        w.putU8(item.flags) catch return .INTERNAL;
        w.putU32(item.code) catch return .INTERNAL;
        w.putU64(item.ts) catch return .INTERNAL;
    }
    return .OK;
}

/// Общая часть SEARCH_MESSAGE / GLOBAL_SEARCH_MESSAGE: чтение лога,
/// разбор записей и сборка ответа (семантика поиска — search.zig).
/// Лога нет — пустой список.
fn searchRun(app: *App, args: search_mod.Args, w: *api.Writer) api.Status {
    // под локом: кэш истории живут мутации (persist/ACK/DELETE_CHAT)
    app.lock();
    defer app.unlock();
    const raw = app.hist.items;
    // записи kind msg → Rec поиска; битые (обрезанные/битый хвост
    // entities) и чаты-надгробия пропускаются — как в GET_HISTORY
    const recs = app.alloc.alloc(search_mod.Rec, raw.len) catch return .INTERNAL;
    defer app.alloc.free(recs);
    var n: usize = 0;
    for (raw) |rec| {
        if (!chatAlive(app, std.mem.readInt(u16, rec[0..2], .little))) continue;
        if (msgRecView(rec)) |v| {
            recs[n] = v;
            n += 1;
        }
    }
    return search_mod.writeResponse(app.alloc, w, recs[0..n], args, api.max_payload);
}

/// Жив ли чат cid (в пределах списка, не удалён). 0 — нет.
fn chatAlive(app: *App, cid: u16) bool {
    if (cid < 1 or cid > app.eng.contacts.items.len) return false;
    return !app.eng.contacts.items[cid - 1].deleted;
}

/// Запись лога kind msg → Rec поиска (срезы указывают в rec):
/// `[cid u16][flags u8][msg_id 16][ts u64][len u16][body][ents]`.
fn msgRecView(rec: []const u8) ?search_mod.Rec {
    const body_off = msgBodyOffset(rec) orelse return null;
    const blen = msgBodyLen(rec) orelse return null;
    if (rec.len < body_off + blen) return null;
    const tail = recEntityTail(rec, blen) orelse return null;
    return .{
        .cid = std.mem.readInt(u16, rec[0..2], .little),
        .flags = rec[2],
        .msg_id = rec[3..19].*,
        .ts_ms = std.mem.readInt(u64, rec[19..27], .little),
        .body = rec[body_off .. body_off + blen],
        .tail = tail,
        .size = 1 + 16 + 8 + 2 + blen + tail.len,
    };
}

/// SEARCH_MESSAGE: payload [cid u32][query str16][limit u32][offset u32].
/// Ответ: [total u32][count u32] × {[flags u8 bit0 mine bit1 delivered
/// bit2 fuzzy][msg_id 16][ts_ms u64][body str16][ent_count u8] × {entity}}
/// — сначала точные совпадения (новые → старые), затем нечёткие; окно
/// режут offset/limit и бюджет 16 МиБ. Матчинг и формат — search.zig.
/// Ошибки: NO_CONTACT, BAD_ARGS (пустой query), TOO_BIG (limit/query).
fn apiSearchMessage(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var args = search_mod.parseArgs(payload, false) orelse return .BAD_FRAME;
    if (search_mod.validate(&args)) |st| return st;
    {
        const cid = args.cid orelse return .BAD_FRAME;
        app.lock();
        defer app.unlock();
        if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
        if (app.eng.contacts.items[cid - 1].deleted) return .NO_CONTACT;
    }
    return searchRun(app, args, w);
}

/// GLOBAL_SEARCH_MESSAGE: payload [query str16][limit u32][offset u32] —
/// поиск по всем чатам; записи ответа те же, но начинаются с [cid u32].
/// Ошибки: BAD_ARGS (пустой query), TOO_BIG (limit/query).
fn apiGlobalSearchMessage(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var args = search_mod.parseArgs(payload, true) orelse return .BAD_FRAME;
    if (search_mod.validate(&args)) |st| return st;
    return searchRun(app, args, w);
}

/// Загрузка профиля из лога: конфигурация, контакты (+relay-присутствие),
/// настройки (set), история-кэш, аватары, блокировки, клиентская БД.
/// Вызывается стартом serve и восстановлением профиля (app/recovery.zig)
/// ПОД app.mu. Публична для тестов приложения.
pub fn loadContacts(app: *App) void {
    const log = app.log orelse return;
    // конфигурация первой: server_mode поднимает присутствие в конце
    // загрузки, device_sync нужен для регистраций линков. Последняя
    // запись побеждает (SET_CONFIG пишет новую); битая — пропускается
    // (defaults остаются).
    if (log.readAll(.cfg, app.alloc)) |cfgs| {
        defer {
            for (cfgs) |r| app.alloc.free(r);
            app.alloc.free(cfgs);
        }
        for (cfgs) |rec| {
            var c = app.cfg;
            c.decode(rec) catch continue;
            app.cfg = c;
        }
    } else |_| {}
    const recs = log.readAll(.contact, app.alloc) catch return;
    defer {
        for (recs) |r| app.alloc.free(r);
        app.alloc.free(recs);
    }
    for (recs) |rec| {
        if (rec.len < 66) continue;
        const nlen: usize = rec[0];
        if (rec.len < 1 + nlen + 64) continue;
        const name = rec[1 .. 1 + nlen];
        const bundle: [64]u8 = rec[1 + nlen ..][0..64].*;
        const idx = app.eng.addContact(name, bundle) catch return;
        app.hb.put(@intCast(idx + 1), .{}) catch {};
        // хвост адреса: [alen][host][port LE] (последняя запись побеждает)
        const c = &app.eng.contacts.items[idx];
        const tail = 1 + nlen + 64;
        if (rec.len >= tail + 1) {
            const alen: usize = rec[tail];
            if (alen > 0 and alen <= 64 and rec.len >= tail + 1 + alen + 2) {
                const port = std.mem.readInt(u16, rec[tail + 1 + alen ..][0..2], .little);
                c.setAddr(rec[tail + 1 .. tail + 1 + alen], port);
            }
            // relay-хвост: [rlen][rhost][rport LE] — присутствие после рестарта
            const rtail = tail + 1 + alen + 2;
            if (rec.len >= rtail + 1) {
                const rlen: usize = rec[rtail];
                if (rlen > 0 and rlen <= 64 and rec.len >= rtail + 1 + rlen + 2) {
                    const rport = std.mem.readInt(u16, rec[rtail + 1 + rlen ..][0..2], .little);
                    var rbuf: [72]u8 = undefined;
                    const rhost = rec[rtail + 1 .. rtail + 1 + rlen];
                    const raddr = std.fmt.bufPrint(&rbuf, "{s}:{d}", .{ rhost, rport }) catch rbuf[0..0];
                    if (raddr.len > 0) {
                        startRelayPresenceLocked(app, @intCast(idx + 1), raddr);
                    }
                }
                // хвост роли линка устройства: [dev_role u8] после relay
                // (старые записи без байта — не устройство)
                const dtail = rtail + 1 + rlen + 2;
                if (rec.len == dtail + 1) {
                    const role = rec[dtail];
                    if (role == dev_role_waiter or role == dev_role_holder) {
                        c.dev_role = role;
                    }
                }
            }
        }
    }
    // настройки ДО истории и outbox: надгробия (set:7) должны закрыть слоты
    // раньше, чем записи начнут фильтроваться по deleted
    //   set:1 [1][avatar_id 16] — мой avatar_id
    //   set:2 [2][имя]          — моё имя профиля
    //   set:3 [3][cid u16]      — закрепить чат
    //   set:4 [4]               — снять закрепление чата
    //   set:5 [5][cid u16][msg_id 16] — закрепить сообщение
    //   set:6 [6][cid u16][msg_id 16] — открепить сообщение
    //   set:7 [7][cid u16]      — надгробие удалённого чата (слот невидим)
    const sets = log.readAll(.set, app.alloc) catch return;
    defer {
        for (sets) |r| app.alloc.free(r);
        app.alloc.free(sets);
    }
    for (sets) |rec| {
        if (rec.len == 17 and rec[0] == 1) app.eng.my_avatar_id = rec[1..17].*;
        if (rec.len >= 2 and rec[0] == 2) app.eng.setMyProfile(rec[1..rec.len], app.eng.my_avatar_id);
        if (rec.len == 3 and rec[0] == 3) {
            const cid = std.mem.readInt(u16, rec[1..3], .little);
            if (cid >= 1 and cid <= app.eng.contacts.items.len) app.pinned_chat = cid;
        }
        if (rec.len == 1 and rec[0] == 4) app.pinned_chat = 0;
        if (rec.len == 19 and rec[0] == 5) {
            const cid: i64 = @intCast(std.mem.readInt(u16, rec[1..3], .little));
            const msg_id: [16]u8 = rec[3..19].*;
            if (cid >= 1 and cid <= app.eng.contacts.items.len) {
                const list = app.pinned_msgs.getOrPut(app.alloc, cid) catch continue;
                if (!list.found_existing) list.value_ptr.* = .empty;
                if (list.value_ptr.items.len < max_pinned_msgs)
                    list.value_ptr.append(app.alloc, msg_id) catch {};
            }
        }
        if (rec.len == 19 and rec[0] == 6) {
            const cid: i64 = @intCast(std.mem.readInt(u16, rec[1..3], .little));
            const msg_id: [16]u8 = rec[3..19].*;
            if (app.pinned_msgs.getPtr(cid)) |list| {
                var i: usize = 0;
                while (i < list.items.len) : (i += 1) {
                    if (std.mem.eql(u8, &list.items[i], &msg_id)) {
                        _ = list.orderedRemove(i);
                        break;
                    }
                }
            }
        }
        if (rec.len == 3 and rec[0] == 7) {
            const cid = std.mem.readInt(u16, rec[1..3], .little);
            if (cid >= 1 and cid <= app.eng.contacts.items.len) {
                app.eng.contacts.items[cid - 1].deleted = true;
                app.eng.contacts.items[cid - 1].online = false;
            }
        }
    }
    // история: кэш записей kind msg в памяти (GET_HISTORY/GET_MESSAGE/SEARCH
    // больше не читают лог); чаты-надгробия в кэш не попадают
    const msgs = log.readAll(.msg, app.alloc) catch return;
    defer {
        for (msgs) |r| app.alloc.free(r);
        app.alloc.free(msgs);
    }
    for (msgs) |rec| {
        if (rec.len < 29) continue;
        const cid = std.mem.readInt(u16, rec[0..2], .little);
        if (!chatAlive(app, cid)) continue;
        histAppend(app, rec, rec[3 .. 3 + 16].*);
    }
    // outbox: добавление/погашение в порядке записи лога; ACK заодно
    // гасит delivered в кэше истории (правда о доставке после рестарта)
    const obs = log.readAll(.outbox, app.alloc) catch return;
    defer {
        for (obs) |r| app.alloc.free(r);
        app.alloc.free(obs);
    }
    for (obs) |rec| {
        if (rec.len < 3) continue;
        const cid: i64 = @intCast(std.mem.readInt(u16, rec[1..3], .little));
        if (cid < 1 or cid > app.eng.contacts.items.len) continue;
        if (rec[0] == 0) {
            if (rec.len < 3 + 16) continue;
            const msg_id: [16]u8 = rec[3 .. 3 + 16].*;
            var i: usize = 0;
            while (i < app.eng.outbox.items.len) {
                if (app.eng.outbox.items[i].cid == cid and std.mem.eql(u8, &app.eng.outbox.items[i].msg_id, &msg_id)) {
                    const old = app.eng.outbox.orderedRemove(i);
                    app.alloc.free(old.body);
                    app.alloc.free(old.ents_tail);
                } else i += 1;
            }
            histDelivered(app, msg_id);
            continue;
        }
        if (app.eng.contacts.items[@intCast(cid - 1)].deleted) continue;
        if (rec.len < 3 + 16 + 8 + 2) continue;
        const msg_id: [16]u8 = rec[3 .. 3 + 16].*;
        const ts_ms = std.mem.readInt(u64, rec[19..27], .little);
        const body_off = msgBodyOffset(rec) orelse continue;
        const blen = msgBodyLen(rec) orelse continue;
        if (blen == 0 or blen > 4096 or rec.len < body_off + blen) continue;
        const body = app.alloc.dupe(u8, rec[body_off .. body_off + blen]) catch continue;
        const reply_to = msgReplyTo(rec);
        // хвост entities: старые записи без хвоста — форматирования нет
        var ents_tail: []u8 = &.{};
        if (rec.len > body_off + blen) {
            const t = recEntityTail(rec, blen) orelse {
                app.alloc.free(body);
                continue;
            };
            ents_tail = app.alloc.dupe(u8, t) catch {
                app.alloc.free(body);
                continue;
            };
        }
        app.eng.outbox.append(app.alloc, .{ .cid = cid, .msg_id = msg_id, .ts_ms = ts_ms, .reply_to = reply_to, .body = body, .ents_tail = ents_tail }) catch {
            app.alloc.free(body);
            app.alloc.free(ents_tail);
        };
    }
    // аватары: кэш id -> байты (свои и чужие)
    const avs = log.readAll(.avatar, app.alloc) catch return;
    defer {
        for (avs) |r| app.alloc.free(r);
        app.alloc.free(avs);
    }
    for (avs) |rec| {
        if (rec.len < 18) continue;
        const alen = std.mem.readInt(u16, rec[16..18], .little);
        if (alen == 0 or alen > 16000 or rec.len < 18 + alen) continue;
        const id: [16]u8 = rec[0..16].*;
        const copy = app.alloc.dupe(u8, rec[18 .. 18 + alen]) catch continue;
        app.avatars.put(app.alloc, id, copy) catch {
            app.alloc.free(copy);
        };
    }
    // блокировки поверх загруженных контактов
    const blocks = log.readAll(.block, app.alloc) catch return;
    defer {
        for (blocks) |r| app.alloc.free(r);
        app.alloc.free(blocks);
    }
    for (blocks) |rec| {
        if (rec.len != 65) continue;
        const bundle: [64]u8 = rec[0..64].*;
        const flag = rec[64] == 1;
        for (app.eng.contacts.items) |*c| {
            if (std.mem.eql(u8, &c.bundle, &bundle)) c.blocked = flag;
        }
    }
    // клиентские записи БД (kind client): кэш для READ_DB + MAC-и для
    // дедупа синхронизации. Капа кэша client_db_cap (жёсткая при записи,
    // мягкая при загрузке: лишнее остаётся в логе, но не в памяти).
    if (log.readAllSeq(.client, app.alloc)) |crecs| {
        defer {
            for (crecs) |r| app.alloc.free(r.payload);
            app.alloc.free(crecs);
        }
        for (crecs) |r| loadClientRec(app, r.seq, r.payload);
    } else |_| {}
    // линейки устройств: bundle == наш, слот жив (не надгробие) —
    // регистрируем в синхронизаторе (очередь записей БД на это устройство)
    for (app.eng.contacts.items, 0..) |*c, i| {
        if (c.deleted or c.dev_role == 0) continue;
        if (std.mem.eql(u8, &c.bundle, &app.id.bundle())) {
            app.sync.addDevice(@intCast(i + 1));
        }
    }
    // server_mode с сохранённой конфигурацией: присутствие всем контактам
    startServerPresenceForAllLocked(app);
}

/// Загрузка клиентской записи (kind client): [tag][ts 8][len 2][data].
/// Кэш + MAC (дедуп приёма SYNC) + счётчик капы.
fn loadClientRec(app: *App, seq: u32, rec: []const u8) void {
    if (rec.len < 11) return;
    const dlen: usize = std.mem.readInt(u16, rec[9..11], .little);
    if (dlen == 0 or dlen > max_client_data or rec.len != 11 + dlen) return;
    if (app.client_bytes + dlen > client_db_cap) return; // кэш полон
    const copy = app.alloc.dupe(u8, rec[11..]) catch return;
    const mac = sync_mod.recordMac(&app.sync.key, @backingInt(sync_mod.RecKind.client), rec);
    app.client_macs.put(app.alloc, mac, {}) catch {
        app.alloc.free(copy);
        return;
    };
    app.client_recs.append(app.alloc, .{
        .seq = seq,
        .tag = rec[0],
        .ts_ms = std.mem.readInt(u64, rec[1..9], .little),
        .data = copy,
    }) catch {
        _ = app.client_macs.remove(mac);
        app.alloc.free(copy);
        return;
    };
    app.client_bytes += dlen;
}

// ------------------------------------------------------------- диспетчер

/// Запрос API, собранный сервером из кадра.
pub const ApiRequest = struct {
    method: api.Method,
    request_id: u32,
    payload: []const u8,
};

/// Маппинг error set'ов ядра на статусы API.
fn statusOf(e: anyerror) api.Status {
    return switch (e) {
        error.Blocked => .CONTACT_BLOCKED,
        error.NoSession => .NO_SESSION,
        error.NoContact => .NO_CONTACT,
        error.TooBig => .TOO_BIG,
        error.TooManyInvites => .TOO_MANY_INVITES,
        error.FileNotFound => .FILE_NOT_FOUND,
        error.NoRelay => .NO_RELAY,
        error.NoTor => .TOR_UNAVAILABLE,
        error.BadArgs, error.BadEntities, error.BadHex, error.BadCode, error.BadName, error.BadAddr => .BAD_ARGS,
        error.Busy => .BUSY,
        error.NoCall => .NO_CALL,
        else => .INTERNAL,
    };
}

/// Применить новую конфигурацию к живому демону. ВЫЗЫВАЕТСЯ ПОД app.mu:
/// эффекты, зависящие от полей (server_mode поднимает присутствие
/// контактов на своём сервере; выключение гасит потоки на следующей
/// итерации). Транспортные флаги (use_fake_tls/use_tor_mask) действуют
/// на НОВЫЕ подключения — установленные сессии живут как поднялись.
fn applyConfigLocked(app: *App, new: config_mod.Config) void {
    app.cfg = new;
    if (new.server_mode) startServerPresenceForAllLocked(app);
}

/// GET_CONFIG (35): ∅ → blob [ver u8][flags u32][server_addr str16]
/// [tor_addr str16] — формат app/config.zig.
fn apiGetConfig(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    if (payload.len != 0) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    var buf: [config_mod.blob_max]u8 = undefined;
    const blob = app.cfg.encode(&buf) catch return .INTERNAL;
    w.putBytes(blob) catch return .INTERNAL;
    return .OK;
}

/// SET_CONFIG (36): blob конфигурации → ∅. Валидация (decode), запись в
/// лог (kind cfg, последняя побеждает), применение, событие
/// CONFIG_CHANGED и репликация на устройства (device_sync). Ответ пуст.
fn apiSetConfig(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    _ = w;
    var c = config_mod.Config.defaults();
    c.decode(payload) catch |e| return switch (e) {
        error.BadFrame => .BAD_FRAME,
        error.BadVersion => .BAD_FRAME,
        error.BadFlags => .BAD_ARGS,
        error.BadAddr => .BAD_ARGS,
        error.NoSpace => .INTERNAL,
    };
    app.lock();
    defer app.unlock();
    applyConfigLocked(app, c);
    if (app.log) |log| {
        _ = log.append(.cfg, payload) catch return .INTERNAL;
    }
    evConfigChanged(app);
    syncEnqueue(app, @backingInt(sync_mod.RecKind.cfg), payload);
    syncPumpLocked(app);
    return .OK;
}

/// WRITE_DB (37): [tag u8][data str32 ≤ 65000] → [rec_id u32][ts_ms u64].
/// Клиентская запись в шифрованной БД (kind client) + кэш; при
/// device_sync — репликация на связанные устройства. Тег 0xFF —
/// зарезервирован под wildcard чтения.
fn apiWriteDb(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const tag = r.readU8() catch return .BAD_FRAME;
    const data = r.readStr32() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    if (data.len == 0 or data.len > max_client_data) return .TOO_BIG;
    if (tag == client_tag_wildcard) return .BAD_ARGS;
    app.lock();
    defer app.unlock();
    if (app.client_bytes + data.len > client_db_cap) return .TOO_BIG;
    const log = app.log orelse return .INTERNAL;
    var buf: [11 + max_client_data]u8 = undefined;
    const ts: u64 = @intCast(app.nowMs());
    buf[0] = tag;
    std.mem.writeInt(u64, buf[1..9], ts, .little);
    std.mem.writeInt(u16, buf[9..11], @intCast(data.len), .little);
    @memcpy(buf[11..][0..data.len], data);
    const rec = buf[0 .. 11 + data.len];
    const seq = log.append(.client, rec) catch return .INTERNAL;
    const mac = sync_mod.recordMac(&app.sync.key, @backingInt(sync_mod.RecKind.client), rec);
    const copy = app.alloc.dupe(u8, data) catch return .INTERNAL;
    app.client_macs.put(app.alloc, mac, {}) catch {
        app.alloc.free(copy);
        return .INTERNAL;
    };
    app.client_recs.append(app.alloc, .{
        .seq = seq,
        .tag = tag,
        .ts_ms = ts,
        .data = copy,
    }) catch {
        _ = app.client_macs.remove(mac);
        app.alloc.free(copy);
        return .INTERNAL;
    };
    app.client_bytes += data.len;
    syncEnqueue(app, @backingInt(sync_mod.RecKind.client), rec);
    syncPumpLocked(app);
    w.putU32(seq) catch return .INTERNAL;
    w.putU64(ts) catch return .INTERNAL;
    return .OK;
}

/// READ_DB (38): [tag u8 (0xFF = все)][limit u32 (0 → 50, ≤ 200)][offset u32]
/// → [total u32][count u32] × {[rec_id u32][ts_ms u64][tag u8][data str16]},
/// старые → новые. Читает кэш памяти (загружается при старте).
fn apiReadDb(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    var r = api.Reader.init(payload);
    const tag = r.readU8() catch return .BAD_FRAME;
    const limit_in = r.readU32() catch return .BAD_FRAME;
    const offset = r.readU32() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    const limit: usize = if (limit_in == 0) 50 else @min(limit_in, 200);
    app.lock();
    defer app.unlock();
    var total: usize = 0;
    for (app.client_recs.items) |rec| {
        if (tag == client_tag_wildcard or rec.tag == tag) total += 1;
    }
    w.putU32(@intCast(total)) catch return .INTERNAL;
    var matched: usize = 0;
    var count: usize = 0;
    for (app.client_recs.items) |rec| {
        if (tag != client_tag_wildcard and rec.tag != tag) continue;
        if (matched < offset) {
            matched += 1;
            continue;
        }
        if (count >= limit) break;
        w.putU32(rec.seq) catch return .INTERNAL;
        w.putU64(rec.ts_ms) catch return .INTERNAL;
        w.putU8(rec.tag) catch return .INTERNAL;
        w.putStr16(rec.data) catch return .INTERNAL;
        count += 1;
    }
    return .OK;
}

/// DELETE_DB (39): [rec_id u32] → ∅. Tombstone лога (идемпотентно) +
/// снятие с кэша. v1: удаление ЛОКАЛЬНО — на других устройствах копия
/// остаётся (клиент протокола может выразить удаление своей записью —
/// данные тега определены приложением).
fn apiDeleteDb(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    _ = w;
    var r = api.Reader.init(payload);
    const rec_id = r.readU32() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    if (app.log) |log| _ = log.appendTombstone(rec_id) catch return .INTERNAL;
    var i: usize = 0;
    while (i < app.client_recs.items.len) {
        if (app.client_recs.items[i].seq == rec_id) {
            const rec = app.client_recs.orderedRemove(i);
            app.client_bytes -= rec.data.len;
            app.alloc.free(rec.data);
            // MAC остаётся: повторная доставка этой записи с устройства
            // должна отфильтроваться и после локального удаления
        } else i += 1;
    }
    return .OK;
}

/// Wildcard-тег чтения клиентских записей (в WRITE_DB запрещён).
const client_tag_wildcard: u8 = 0xFF;

/// Диспетчер API-методов: разбирает payload, исполняет, шлёт ровно один
/// ответ. Возвращает false — сервер закрывает соединение (CLOSE).
pub fn dispatchApi(app: *App, conn: *api_srv.Conn, req: ApiRequest) bool {
    var w = api.Writer.init(app.alloc);
    defer w.deinit();
    switch (req.method) {
        .CLOSE => {
            // ответ и разрыв — без обработки payload
            conn.sendResponse(@backingInt(req.method), req.request_id, .OK, &.{});
            return false;
        },
        .GET_VERSION => {
            if (req.payload.len != 0) {
                respond(conn, req, .BAD_FRAME, &.{});
                return true;
            }
            w.putU16(api.api_version[0]) catch return internal(conn, req);
            w.putU16(api.api_version[1]) catch return internal(conn, req);
            w.putU16(api.api_version[2]) catch return internal(conn, req);
            respond(conn, req, .OK, w.items());
        },
        .GET_IDENTITY => respond(conn, req, apiGetIdentity(app, req.payload, &w), w.items()),
        .CREATE_INVITE => respond(conn, req, apiCreateInvite(app, req.payload, &w), w.items()),
        .ACCEPT_INVITE => respond(conn, req, apiAcceptInvite(app, req.payload, &w), w.items()),
        .LIST_CONTACTS => respond(conn, req, apiListContacts(app, req.payload, &w), w.items()),
        .SEND_MESSAGE => respond(conn, req, apiSendMessage(app, req.payload, &w), w.items()),
        .SEND_REPLY_MESSAGE => respond(conn, req, apiSendReplyMessage(app, req.payload, &w), w.items()),
        .SET_REACTION => respond(conn, req, apiReaction(app, req.payload, true), w.items()),
        .REMOVE_REACTION => respond(conn, req, apiReaction(app, req.payload, false), w.items()),
        .GET_REACTIONS => respond(conn, req, apiGetReactions(app, req.payload, &w), w.items()),
        .GET_HISTORY => respond(conn, req, apiGetHistory(app, req.payload, &w), w.items()),
        .GET_MESSAGE => respond(conn, req, apiGetMessage(app, req.payload, &w), w.items()),
        .SEARCH_MESSAGE => respond(conn, req, apiSearchMessage(app, req.payload, &w), w.items()),
        .GLOBAL_SEARCH_MESSAGE => respond(conn, req, apiGlobalSearchMessage(app, req.payload, &w), w.items()),
        .PIN_CHAT => respond(conn, req, apiPinChat(app, req.payload, &w), w.items()),
        .GET_PINNED_CHAT => respond(conn, req, apiGetPinnedChat(app, req.payload, &w), w.items()),
        .UNPIN_CHAT => respond(conn, req, apiUnpinChat(app, req.payload, &w), w.items()),
        .DELETE_CHAT => respond(conn, req, apiDeleteChat(app, req.payload, &w), w.items()),
        .GET_CONTACT_STATE => respond(conn, req, apiGetContactState(app, req.payload, &w), w.items()),
        .ACCEPT_INVITE_EX => respond(conn, req, apiAcceptInviteEx(app, req.payload, &w), w.items()),
        .SUBSCRIBE_CONTACT_UPDATES => respond(conn, req, apiSubscribeContactUpdates(app, conn, req.payload, &w), w.items()),
        .GET_BOOTSTRAP => respond(conn, req, apiGetBootstrap(app, req.payload, &w), w.items()),
        .GET_CONTACTS_DELTA => respond(conn, req, apiGetContactsDelta(app, req.payload, &w), w.items()),
        .GET_REACHABLE_ENDPOINTS => respond(conn, req, apiGetReachableEndpoints(app, req.payload, &w), w.items()),
        .CREATE_INVITE_EX => respond(conn, req, apiCreateInviteEx(app, req.payload, &w), w.items()),
        .GET_INVITE_STATE => respond(conn, req, apiGetInviteState(app, req.payload, &w), w.items()),
        .GET_HISTORY_PAGE => respond(conn, req, apiGetHistoryPage(app, req.payload, &w), w.items()),
        .SEND_CONTACT => respond(conn, req, apiSendContact(app, req.payload, &w), w.items()),
        .PIN_MESSAGE => respond(conn, req, apiPinMessage(app, req.payload, &w), w.items()),
        .UNPIN_MESSAGE => respond(conn, req, apiUnpinMessage(app, req.payload, &w), w.items()),
        .GET_PINNED_MESSAGES => respond(conn, req, apiGetPinnedMessages(app, req.payload, &w), w.items()),
        .SET_NAME => respond(conn, req, apiSetName(app, req.payload, &w), w.items()),
        .SET_AVATAR => respond(conn, req, apiSetAvatar(app, req.payload, &w), w.items()),
        .GET_MY_AVATAR => respond(conn, req, apiGetMyAvatar(app, req.payload, &w), w.items()),
        .CREATE_RECOVERY_BACKUP => respond(conn, req, apiCreateRecoveryBackup(app, req.payload, &w), w.items()),
        .RESTORE_RECOVERY_BACKUP => respond(conn, req, apiRestoreRecoveryBackup(app, req.payload, &w), w.items()),
        .GET_AVATAR_ID => respond(conn, req, apiGetAvatarId(app, req.payload, &w), w.items()),
        .SEND_FILE => respond(conn, req, apiSendFile(app, req.payload, &w), w.items()),
        .START_CALL => respond(conn, req, apiStartCall(app, req.payload, &w), w.items()),
        .ANSWER_CALL => respond(conn, req, apiAnswerCall(app, req.payload, &w), w.items()),
        .END_CALL => respond(conn, req, apiEndCall(app, req.payload, &w), w.items()),
        .BLOCK_CONTACT => respond(conn, req, apiBlock(app, req.payload, true), w.items()),
        .UNBLOCK_CONTACT => respond(conn, req, apiBlock(app, req.payload, false), w.items()),
        .CONNECT => respond(conn, req, apiConnect(app, req.payload, &w), w.items()),
        .LISTEN => respond(conn, req, apiListen(app, req.payload, &w), w.items()),
        .GET_CONFIG => respond(conn, req, apiGetConfig(app, req.payload, &w), w.items()),
        .SET_CONFIG => respond(conn, req, apiSetConfig(app, req.payload, &w), w.items()),
        .WRITE_DB => respond(conn, req, apiWriteDb(app, req.payload, &w), w.items()),
        .READ_DB => respond(conn, req, apiReadDb(app, req.payload, &w), w.items()),
        .DELETE_DB => respond(conn, req, apiDeleteDb(app, req.payload, &w), w.items()),
    }
    return true;
}

/// Отправить ответ метода (единая точка).
fn respond(conn: *api_srv.Conn, req: ApiRequest, status: api.Status, payload: []const u8) void {
    conn.sendResponse(@backingInt(req.method), req.request_id, status, payload);
}

/// INTERNAL при переполнении сборщика ответа.
fn internal(conn: *api_srv.Conn, req: ApiRequest) bool {
    conn.sendResponse(@backingInt(req.method), req.request_id, .INTERNAL, &.{});
    return true;
}

/// Поднять сетевую часть демона: тикер presence (PING/автодозвон/слив
/// retired), автолистенер 7777-7786 и LAN-поиск. Вызывается на провиженном
/// старте serve и после восстановления профиля. Потоки — best-effort:
/// неудача спавна/бинда не роняет демон (UDS-апи работает, ошибка — в лог).
fn startNetworking(app: *App) void {
    const th = std.Thread.spawn(.{}, tickerLoop, .{app}) catch {
        std.debug.print("startNetworking: тикер не поднялся\n", .{});
        return;
    };
    th.detach();

    // автолистенер: любой контакт из списка может подключиться сам
    var lsn: ?tcp.Listener = null;
    var listen_port: u16 = 7777;
    var attempt: u16 = 7777;
    while (attempt < 7787) : (attempt += 1) {
        var pbuf: [24]u8 = undefined;
        const a = std.fmt.bufPrint(&pbuf, "0.0.0.0:{d}", .{attempt}) catch unreachable;
        if (tcp.listen(a)) |l| {
            lsn = l;
            listen_port = attempt;
            break;
        } else |_| {}
    }
    if (lsn) |l| {
        app.listen_port = listen_port;
        // 2.7.0: слушатель поднят — GET_REACHABLE_ENDPOINTS отдаёт адреса
        app.lock();
        app.listening = true;
        app.unlock();
        const lp = app.alloc.create(tcp.Listener) catch return;
        lp.* = l;
        const lt = std.Thread.spawn(.{}, autoAcceptLoop, .{ app, lp }) catch return;
        lt.detach();
        const linker = std.Thread.spawn(.{}, linkerLoop, .{app}) catch return;
        linker.detach();
        std.debug.print("авто-режим: слушаю 0.0.0.0:{d}, LAN-поиск включён\n", .{listen_port});
    } else {
        std.debug.print("авто-режим: порты 7777-7786 заняты, LAN-поиск выключен\n", .{});
    }
}

/// CONNECT: payload [cid u32][addr str16] — прямое подключение к контакту
/// (обычно не нужно: автодозвон/LAN сами). Ответ пуст.
fn apiConnect(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    _ = w;
    var r = api.Reader.init(payload);
    const cid = r.readU32() catch return .BAD_FRAME;
    const addr = r.readStr16() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    if (addr.len == 0) return .BAD_ARGS;
    var work = ConnWork{ .cid = @intCast(cid) };
    if (addr.len > work.addr_buf.len) return .BAD_ARGS;
    {
        app.lock();
        defer app.unlock();
        if (cid < 1 or cid > app.eng.contacts.items.len) return .NO_CONTACT;
        // адрес контакта обновить (автодозвон видит последний известный)
        saveContactAddr(app, @intCast(cid), addr);
    }
    @memcpy(work.addr_buf[0..addr.len], addr);
    work.addr_len = @intCast(addr.len);
    // 2.7.0: dial НЕ блокирует ответ — работа уходит планировщику;
    // стадии/результат — GET_CONTACT_STATE и события. Обычно не нужен:
    // ACCEPT_INVITE уже подключает из кода.
    connEnqueue(app, work) catch return .BUSY;
    return .OK;
}

/// LISTEN: payload [addr str16][cid u32] — слушать входящие для контакта
/// (обычно не нужно: автолистенер уже слушает). Ответ пуст.
fn apiListen(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    _ = w;
    var r = api.Reader.init(payload);
    const addr = r.readStr16() catch return .BAD_FRAME;
    const cid = r.readU32() catch return .BAD_FRAME;
    if (r.hasMore()) return .BAD_FRAME;
    if (addr.len == 0) return .BAD_ARGS;
    const lsn = tcp.listen(addr) catch return .TRANSPORT_FAILED;
    const lp = app.alloc.create(tcp.Listener) catch return .INTERNAL;
    lp.* = lsn;
    const th = std.Thread.spawn(.{}, struct {
        fn go(a: *App, l: *tcp.Listener, c: i64) void {
            acceptLoop(a, l, c);
        }
    }.go, .{ app, lp, @as(i64, @intCast(cid)) }) catch return .INTERNAL;
    th.detach();
    return .OK;
}

fn badUsage() error{BadUsage} {
    std.debug.print("{s}\n", .{usage});
    return error.BadUsage;
}

pub fn main(start: std.process.Init) !void {
    const io = start.io;
    const home: []const u8 = start.environ_map.get("HOME") orelse "";
    const argv = start.minimal.args.vector;

    if (argv.len < 2) {
        std.debug.print("{s}\n", .{usage});
        return;
    }
    const cmd: []const u8 = std.mem.span(argv[1]);

    // relay <host:port>: байтовый сплит без состояния stille-messenger (скрытие IP).
    // Запускается на любом сервере: stille-messenger-core relay 0.0.0.0:9000
    if (std.mem.eql(u8, cmd, "relay")) {
        const addr = if (argv.len >= 3) std.mem.span(argv[2]) else return badUsage();
        var listener = tcp.listen(addr) catch {
            std.debug.print("relay: не удалось слушать {s}\n", .{addr});
            return;
        };
        std.debug.print("relay: слушаю {s}, спариваю по marker-у инвайта\n", .{addr});
        var dbg_state = std.heap.DebugAllocator(.{ .thread_safe = true }){};
        const alloc = dbg_state.allocator();
        stille_messenger.net.relay.serve(alloc, &listener, null);
        return;
    }

    if (std.mem.eql(u8, cmd, "init")) {
        var seed: [32]u8 = undefined;
        io.random(&seed);
        try saveSeed(io, home, seed);
        var id = try identity.Identity.fromSeed(seed);
        defer id.deinit();
        var fp_buf: [96]u8 = undefined;
        std.debug.print("identity created, seed saved to ~/.stille-messenger/zig-seed (0600)\nfingerprint: {s}\n", .{try id.fingerprintTo(&fp_buf)});
        return;
    }

    // serve без сида — режим восстановления: эфемерная личность (никуда
    // не сохраняется) ждёт RESTORE_RECOVERY_BACKUP от GUI; остальные
    // команды, требующие личности, отвечают NOT_INITIALIZED. Битый сид
    // (не 32 байта) — фатально, молча создавать новый поверх нельзя.
    var provisioned = true;
    var seed: [32]u8 = undefined;
    if (std.mem.eql(u8, cmd, "serve")) {
        if (loadSeed(io, home)) |loaded| {
            seed = loaded;
        } else |e| switch (e) {
            error.FileNotFound => {
                provisioned = false;
                io.random(&seed);
                std.debug.print("serve: сид не найден — режим восстановления (GUI: RESTORE_RECOVERY_BACKUP)\n", .{});
            },
            else => return e,
        }
    } else {
        // все остальные команды требуют существующей личности
        seed = try loadSeed(io, home);
    }
    var id = try identity.Identity.fromSeed(seed);
    defer id.deinit();

    if (std.mem.eql(u8, cmd, "serve")) {
        // потоки: rx-сессий, тикер presence, accept-loop — аллокатор общий
        var dbg_state = std.heap.DebugAllocator(.{ .thread_safe = true }){};
        const alloc = dbg_state.allocator();

        var eng = engine_mod.Engine.init(alloc, io, id, undefined);
        var log_ptr: ?*store_mod.Log = null;
        if (provisioned) {
            var store_path_buf: [512]u8 = undefined;
            const store_path = try std.fmt.bufPrint(&store_path_buf, "{s}/{s}/zig-log", .{ home, data_dir_name });
            if (store_mod.Log.open(alloc, store_path, &seed)) |l| {
                const lp = try alloc.create(store_mod.Log);
                lp.* = l;
                log_ptr = lp;
            } else |e| {
                std.debug.print("лог не открылся: {s} (продолжаю без хранения)\n", .{@errorName(e)});
            }
        }

        var pcm_buf: [512]u8 = undefined;
        const pcm_dir = try std.fmt.bufPrint(&pcm_buf, "{s}/{s}/pcm", .{ home, data_dir_name });
        std.Io.Dir.createDirAbsolute(io, pcm_dir, .default_dir) catch {};
        var pcm_heap: []const u8 = "";
        if (home.len > 0) {
            pcm_heap = std.fmt.allocPrint(alloc, "{s}/{s}/pcm", .{ home, data_dir_name }) catch "";
        }

        var app = App{
            .alloc = alloc,
            .io = io,
            .id = &id,
            .eng = &eng,
            .log = log_ptr,
            .provisioned = provisioned,
            .home_len = @min(home.len, app_home_max),
            .hb = std.AutoHashMap(i64, hb.State).init(alloc),
            .sess_ctx = std.AutoHashMap(i64, *SessCtx).init(alloc),
            .call_pcm_dir = if (pcm_heap.len > 0) pcm_heap else null,
        };
        // синхронизация устройств: ключ — HKDF от сида (один сид на все
        // устройства пользователя); переводчик cid→bundle вызывается
        // только под app.mu. При восстановлении ключ пересчитывается
        // от нового сида (applyBackup).
        app.sync = sync_mod.Sync.init(alloc, &seed);
        app.sync.tr_ctx = &app;
        app.sync.tr_fn = syncTranslateBundle;
        @memcpy(app.home_buf[0..app.home_len], home[0..app.home_len]);
        // epoch ревизий контактов: случайно на старте демона (RESYNC при
        // перезапуске клиента/демона не отдаёт старую ревизию как валидную)
        io.random(&app.contacts_epoch);
        eng.ev = app.events();

        // профиль грузится и сеть поднимается только на провиженном
        // старте; после восстановления (RESTORE_RECOVERY_BACKUP) их
        // поднимает цикл ожидания ниже
        if (provisioned) {
            loadContacts(&app);
            startNetworking(&app);
        }

        // Единственный интерфейс: бинарное UDS-апи для GUI-клиента
        api_srv.start(&app, home);
        std.debug.print("serve: демон работает, UDS-апи готово\n", .{});
        var net_started = provisioned;
        while (app.running) {
            sysfd.sleepMs(250);
            if (!net_started) {
                // восстановление довело профиль до готовности: поднять сеть
                app.lock();
                const up = app.provisioned;
                app.unlock();
                if (up) {
                    net_started = true;
                    startNetworking(&app);
                }
            }
        }

        eng.deinit();
        // новая память приложения: кэш истории и закрепления
        for (app.hist.items) |rec| app.alloc.free(rec);
        app.hist.deinit(app.alloc);
        app.hist_idx.deinit(app.alloc);
        var pit = app.pinned_msgs.valueIterator();
        while (pit.next()) |list| list.deinit(app.alloc);
        app.pinned_msgs.deinit(app.alloc);
        // конфигурация/синхронизация: очереди устройств и клиентская БД
        app.sync.deinit();
        for (app.client_recs.items) |rec| app.alloc.free(rec.data);
        app.client_recs.deinit(app.alloc);
        app.client_macs.deinit(app.alloc);
        app.server_runs.deinit(app.alloc);
        // планировщик подключений (2.7.0): очередь/состояния/ожидания эха
        app.conn_work.deinit(app.alloc);
        app.conn_inflight.deinit(app.alloc);
        app.conn_st.deinit(app.alloc);
        app.conn_await.deinit(app.alloc);
        var join_it = app.join_map.valueIterator();
        while (join_it.next()) |ji| std.crypto.secureZero(u8, &ji.secret);
        app.join_map.deinit(app.alloc);
        for (&app.invites) |*reg| std.crypto.secureZero(u8, &reg.secret);
        app.hb.deinit();
        app.sess_ctx.deinit();
        return;
    }

    std.debug.print("{s}\n", .{usage});
}

test "own avatar API survives encrypted log reopen with fresh application state" {
    const t = std.testing;
    const alloc = t.allocator;
    const seed: [32]u8 = @splat(0x73);
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [4096]u8 = undefined;
    const dir_len = try tmp.dir.realPath(t.io, &dir_buf);
    const path = try std.fmt.allocPrint(alloc, "{s}/avatar-log", .{dir_buf[0..dir_len]});
    defer alloc.free(path);
    var expected_id: [16]u8 = undefined;
    const image: [envelope.max_avatar_data]u8 = @splat(0x91);

    // Each iteration owns a new engine, application and reopened store.
    for (0..2) |run| {
        var id = try identity.Identity.fromSeed(seed);
        defer id.deinit();
        var eng = engine_mod.Engine.init(alloc, t.io, id, .{ .ctx = undefined });
        defer eng.deinit();
        var log = try store_mod.Log.open(alloc, path, &seed);
        defer log.deinit();
        var app: App = .{
            .alloc = alloc,
            .io = t.io,
            .id = &id,
            .eng = &eng,
            .log = &log,
            .hb = std.AutoHashMap(i64, hb.State).init(alloc),
            .sess_ctx = std.AutoHashMap(i64, *SessCtx).init(alloc),
        };
        defer {
            var it = app.avatars.valueIterator();
            while (it.next()) |data| alloc.free(data.*);
            app.avatars.deinit(alloc);
            app.hb.deinit();
            app.sess_ctx.deinit();
        }
        var response = api.Writer.init(alloc);
        defer response.deinit();
        if (run == 0) {
            try t.expectEqual(api.Status.NOT_FOUND, apiGetMyAvatar(&app, &.{}, &response));
            try t.expectEqual(api.Status.BAD_FRAME, apiGetMyAvatar(&app, &.{0}, &response));
            try t.expectEqual(@as(usize, 0), response.items().len);
            // A configured id without cached bytes must not return stale data.
            eng.my_avatar_id = @splat(1);
            try t.expectEqual(api.Status.NOT_FOUND, apiGetMyAvatar(&app, &.{}, &response));
            for ([_][]const u8{ "old avatar", &image }) |bytes| {
                var request = api.Writer.init(alloc);
                defer request.deinit();
                try request.putStr32(bytes);
                var set_response = api.Writer.init(alloc);
                defer set_response.deinit();
                try t.expectEqual(api.Status.OK, apiSetAvatar(&app, request.items(), &set_response));
                expected_id = set_response.items()[0..16].*;
            }
        } else {
            loadContacts(&app);
        }
        try t.expectEqual(api.Status.OK, apiGetMyAvatar(&app, &.{}, &response));
        try t.expectEqualSlices(u8, &expected_id, response.items()[0..16]);
        var reader = api.Reader.init(response.items()[16..]);
        try t.expectEqualSlices(u8, &image, try reader.readStr16());
        try t.expect(!reader.hasMore());
    }
}

test "recovery API: CREATE/RESTORE через хендлеры и статусы" {
    const t = std.testing;
    const alloc = t.allocator;
    const secret: [recovery_codec.secret_length]u8 = @splat(0x42);
    const seed: [32]u8 = @splat(0x73);
    // локальная фикстура: seed-файл/лог в tmp-каталоге, потоки сети
    // подавлены (no_network), адреса полей стабильны (var-локаль теста)
    const Fixture = struct {
        id: identity.Identity,
        eng: engine_mod.Engine,
        log: ?store_mod.Log,
        app: App,
        home: []u8,
        tmp: std.testing.TmpDir,

        fn init(self: *@This(), a: std.mem.Allocator, io: std.Io, fix_seed: [32]u8, provisioned: bool) !void {
            self.tmp = t.tmpDir(.{});
            errdefer self.tmp.cleanup();
            var db: [4096]u8 = undefined;
            const dl = try self.tmp.dir.realPath(io, &db);
            self.home = try a.dupe(u8, db[0..dl]);
            errdefer a.free(self.home);
            var pb: [512]u8 = undefined;
            const data_dir = try std.fmt.bufPrint(&pb, "{s}/{s}", .{ self.home, data_dir_name });
            std.Io.Dir.createDirAbsolute(io, data_dir, @fromBackingInt(@intCast(0o700))) catch {};
            if (provisioned) {
                var sb: [512]u8 = undefined;
                const sp = try std.fmt.bufPrint(&sb, "{s}/{s}/zig-seed", .{ self.home, data_dir_name });
                const f = try std.Io.Dir.createFileAbsolute(io, sp, .{ .exclusive = true });
                defer f.close(io);
                try f.writePositionalAll(io, &fix_seed, 0);
                f.setPermissions(io, .fromMode(0o600)) catch {};
            }
            self.log = null;
            self.id = try identity.Identity.fromSeed(fix_seed);
            errdefer self.id.deinit();
            self.eng = engine_mod.Engine.init(a, io, self.id, .{ .ctx = undefined });
            errdefer self.eng.deinit();
            if (provisioned) {
                var lb: [512]u8 = undefined;
                const lp = try std.fmt.bufPrint(&lb, "{s}/{s}/zig-log", .{ self.home, data_dir_name });
                self.log = try store_mod.Log.open(a, lp, &fix_seed);
            }
            self.app = .{
                .alloc = a,
                .io = io,
                .id = &self.id,
                .eng = &self.eng,
                .log = if (self.log) |*l| l else null,
                .hb = std.AutoHashMap(i64, hb.State).init(a),
                .sess_ctx = std.AutoHashMap(i64, *SessCtx).init(a),
                .provisioned = provisioned,
                .no_network = true,
            };
            self.app.sync = sync_mod.Sync.init(a, &fix_seed);
            self.app.sync.tr_ctx = &self.app;
            self.app.sync.tr_fn = syncTranslateBundle;
            self.app.home_len = @min(self.home.len, app_home_max);
            @memcpy(self.app.home_buf[0..self.app.home_len], self.home[0..self.app.home_len]);
        }

        fn deinit(self: *@This(), a: std.mem.Allocator) void {
            self.app.sync.deinit();
            self.app.hb.deinit();
            self.app.sess_ctx.deinit();
            if (self.app.log) |lp| {
                lp.deinit();
                if (self.log == null or lp != &self.log.?) a.destroy(lp);
            } else if (self.log) |*l| {
                l.deinit();
            }
            self.eng.deinit();
            self.id.deinit();
            a.free(self.home);
            self.tmp.cleanup();
        }
    };

    // провижненный профиль: сид на диске, лог, имя
    var src: Fixture = undefined;
    try src.init(alloc, t.io, seed, true);
    defer src.deinit(alloc);
    src.eng.setMyProfile("recovery-user", src.eng.my_avatar_id);
    {
        var nb: [1 + 32]u8 = undefined;
        nb[0] = 2;
        @memcpy(nb[1 .. 1 + "recovery-user".len], "recovery-user");
        _ = try src.log.?.append(.set, nb[0 .. 1 + "recovery-user".len]);
    }

    // CREATE: [secret 32] → [backup str32]
    var request = api.Writer.init(alloc);
    defer request.deinit();
    try request.putBytes(&secret);
    var response = api.Writer.init(alloc);
    defer response.deinit();
    try t.expectEqual(api.Status.OK, apiCreateRecoveryBackup(&src.app, request.items(), &response));
    var rr = api.Reader.init(response.items());
    const blob = try rr.readStr32();
    try t.expect(!rr.hasMore());
    try t.expect(blob.len >= recovery_codec.min_backup_len);

    // свежий демон: GET_IDENTITY — NOT_INITIALIZED (сигнал онбординга)
    var dst: Fixture = undefined;
    try dst.init(alloc, t.io, @splat(0), false);
    defer dst.deinit(alloc);
    {
        var g = api.Writer.init(alloc);
        defer g.deinit();
        try t.expectEqual(api.Status.NOT_INITIALIZED, apiGetIdentity(&dst.app, &.{}, &g));
        try t.expectEqual(@as(usize, 0), g.items().len);
    }

    // RESTORE: [backup str32][secret 32] → [bundle 64][fp 32][name str16]
    var req2 = api.Writer.init(alloc);
    defer req2.deinit();
    try req2.putStr32(blob);
    try req2.putBytes(&secret);
    var resp2 = api.Writer.init(alloc);
    defer resp2.deinit();
    try t.expectEqual(api.Status.OK, apiRestoreRecoveryBackup(&dst.app, req2.items(), &resp2));
    try t.expectEqualSlices(u8, &src.id.bundle(), resp2.items()[0..64]);
    var rn = api.Reader.init(resp2.items()[96..]);
    try t.expectEqualStrings("recovery-user", try rn.readStr16());
    try t.expect(!rn.hasMore());
    try t.expect(dst.app.provisioned);

    // повторный RESTORE на живой профиль — ALREADY_PROVISIONED
    try t.expectEqual(api.Status.ALREADY_PROVISIONED, apiRestoreRecoveryBackup(&dst.app, req2.items(), &resp2));

    // чужой секрет — BAD_RECOVERY, профиль не создаётся
    var dst2: Fixture = undefined;
    try dst2.init(alloc, t.io, @splat(0), false);
    defer dst2.deinit(alloc);
    var req3 = api.Writer.init(alloc);
    defer req3.deinit();
    try req3.putStr32(blob);
    try req3.putBytes(&@as([32]u8, @splat(0xEE)));
    try t.expectEqual(api.Status.BAD_RECOVERY, apiRestoreRecoveryBackup(&dst2.app, req3.items(), &resp2));
    try t.expect(!dst2.app.provisioned);

    // пустой блоб — BAD_ARGS
    var req4 = api.Writer.init(alloc);
    defer req4.deinit();
    try req4.putStr32("");
    try req4.putBytes(&secret);
    try t.expectEqual(api.Status.BAD_ARGS, apiRestoreRecoveryBackup(&dst2.app, req4.items(), &resp2));

    // CREATE на непровиженном — NOT_INITIALIZED
    var w5 = api.Writer.init(alloc);
    defer w5.deinit();
    try t.expectEqual(api.Status.NOT_INITIALIZED, apiCreateRecoveryBackup(&dst2.app, request.items(), &w5));

    // малформ: лишний байт в CREATE — BAD_FRAME
    var req6 = api.Writer.init(alloc);
    defer req6.deinit();
    try req6.putBytes(&secret);
    try req6.putU8(0);
    try t.expectEqual(api.Status.BAD_FRAME, apiCreateRecoveryBackup(&src.app, req6.items(), &w5));
}

// ------------------------------------------------------------ тесты 2.7.0
// Хендлер-уровень (как recovery-тесты): фикстура без сети/лога, все
// новые методы дергаются напрямую, потоки не поднимаются (адреса в
// кодах нет — работы подключения не ставится в очередь).

test "2.7.0: ACCEPT_INVITE_EX, состояние, бутстрап, дельта, страница истории" {
    const t = std.testing;
    const alloc = t.allocator;
    const seed: [32]u8 = @splat(0x55);
    var id = try identity.Identity.fromSeed(seed);
    defer id.deinit();
    var eng = engine_mod.Engine.init(alloc, t.io, id, .{ .ctx = undefined });
    defer eng.deinit();
    var app = App{
        .alloc = alloc,
        .io = t.io,
        .id = &id,
        .eng = &eng,
        .log = null,
        .hb = std.AutoHashMap(i64, hb.State).init(alloc),
        .sess_ctx = std.AutoHashMap(i64, *SessCtx).init(alloc),
        .provisioned = true,
        .no_network = true,
    };
    defer app.hb.deinit();
    defer app.sess_ctx.deinit();
    defer app.conn_st.deinit(alloc);
    defer app.conn_await.deinit(alloc);
    defer app.conn_inflight.deinit(alloc);
    defer app.conn_work.deinit(alloc);
    defer app.join_map.deinit(alloc);
    defer {
        for (app.hist.items) |rec| alloc.free(rec);
        app.hist.deinit(alloc);
        app.hist_idx.deinit(alloc);
    }

    // v2-код без адреса: контакт + DISCOVERING (ждёт LAN-анонс)
    var bundle: [64]u8 = @splat(0xAB);
    bundle[0] = 1;
    const secret: [invite_mod.secret_len]u8 = @splat(0x11);
    var cb: [256]u8 = undefined;
    const code = try invite_mod.encode2(&cb, bundle, secret, "mom", null);

    var req = api.Writer.init(alloc);
    defer req.deinit();
    try req.putStr16(code);
    try req.putStr16("son");
    var resp = api.Writer.init(alloc);
    defer resp.deinit();
    try t.expectEqual(api.Status.OK, apiAcceptInviteEx(&app, req.items(), &resp));
    {
        var rr = api.Reader.init(resp.items());
        const cid = try rr.readU32();
        const disp = try rr.readU8();
        const state = try rr.readU8();
        const attempt = try rr.readU32();
        try t.expect(!rr.hasMore());
        try t.expectEqual(@as(u32, 1), cid);
        try t.expectEqual(@as(u8, @backingInt(api.AcceptDisposition.accepted)), disp);
        try t.expectEqual(@as(u8, @backingInt(api.ConnState.pending)), state);
        try t.expectEqual(@as(u32, 0), attempt);
    }
    // повторное погашение того же кода: тот же cid, дубль контакта не создаётся
    var resp2 = api.Writer.init(alloc);
    defer resp2.deinit();
    try t.expectEqual(api.Status.OK, apiAcceptInviteEx(&app, req.items(), &resp2));
    var rr2 = api.Reader.init(resp2.items());
    try t.expectEqual(@as(u32, 1), try rr2.readU32());
    try t.expectEqual(@as(usize, 1), app.eng.contacts.items.len);
    // JOIN-данные заряжены (отправит первым конвертом после рукопожатия)
    try t.expect(app.join_map.contains(1));

    // GET_CONTACT_STATE: дешёвый опрос стадии
    var gs = api.Writer.init(alloc);
    defer gs.deinit();
    var gc = api.Writer.init(alloc);
    defer gc.deinit();
    try gc.putU32(1);
    try t.expectEqual(api.Status.OK, apiGetContactState(&app, gc.items(), &gs));
    {
        var rr = api.Reader.init(gs.items());
        try t.expectEqual(@as(u8, @backingInt(api.ConnState.pending)), try rr.readU8());
        try t.expectEqual(@as(u32, 0), try rr.readU32());
        try t.expectEqual(@as(u16, 0), try rr.readU16());
        try t.expectEqual(@as(u32, 0), try rr.readU32());
        try t.expect(!rr.hasMore());
    }
    try t.expectEqual(api.Status.NO_CONTACT, apiGetContactState(&app, &.{ 9, 0, 0, 0 }, &gs));
    try t.expectEqual(api.Status.BAD_FRAME, apiGetContactState(&app, &.{1}, &gs));

    // GET_BOOTSTRAP: версия API, epoch, ревизия, счёт, представление
    var bs = api.Writer.init(alloc);
    defer bs.deinit();
    try t.expectEqual(api.Status.OK, apiGetBootstrap(&app, &.{}, &bs));
    var br = api.Reader.init(bs.items());
    try t.expectEqual(api.api_version[0], try br.readU16());
    try t.expectEqual(api.api_version[1], try br.readU16());
    try t.expectEqual(api.api_version[2], try br.readU16());
    const epoch = try br.readBytes(16);
    const rev0 = try br.readU64();
    const cnt = try br.readU32();
    try t.expectEqual(@as(u32, 1), cnt);
    {
        const vcid = try br.readU32();
        const vflags = try br.readU8();
        _ = try br.readI64();
        const vname = try br.readStr16();
        _ = try br.readBytes(16);
        const vstate = try br.readU8();
        _ = try br.readU32();
        _ = try br.readU16();
        _ = try br.readU32();
        try t.expect(!br.hasMore());
        try t.expectEqual(@as(u32, 1), vcid);
        try t.expectEqual(@as(u8, 4), vflags); // pending (bit2)
        try t.expectEqualStrings("mom", vname);
        try t.expectEqual(@as(u8, @backingInt(api.ConnState.pending)), vstate);
    }
    try t.expect(rev0 > 0);

    // SUBSCRIBE_CONTACT_UPDATES: epoch/revision + флаг конна
    var conn = api_srv.Conn{ .fd = -1, .srv = undefined };
    var ss = api.Writer.init(alloc);
    defer ss.deinit();
    try t.expectEqual(api.Status.OK, apiSubscribeContactUpdates(&app, &conn, &.{}, &ss));
    try t.expect(conn.subscribed);
    {
        var rr = api.Reader.init(ss.items());
        try t.expectEqualSlices(u8, epoch, try rr.readBytes(16));
        try t.expectEqual(rev0, try rr.readU64());
        try t.expect(!rr.hasMore());
    }
    try t.expectEqual(api.Status.BAD_FRAME, apiSubscribeContactUpdates(&app, &conn, &.{1}, &ss));

    // GET_CONTACTS_DELTA: свежая ревизия — пусто; нулевая — полное кольцо
    var ds = api.Writer.init(alloc);
    defer ds.deinit();
    var dq = api.Writer.init(alloc);
    defer dq.deinit();
    try dq.putBytes(epoch);
    try dq.putU64(rev0);
    try t.expectEqual(api.Status.OK, apiGetContactsDelta(&app, dq.items(), &ds));
    {
        var rr = api.Reader.init(ds.items());
        try t.expectEqualSlices(u8, epoch, try rr.readBytes(16));
        try t.expectEqual(rev0, try rr.readU64());
        try t.expectEqual(@as(u32, 0), try rr.readU32());
        try t.expect(!rr.hasMore());
    }
    ds.list.clearRetainingCapacity();
    dq.list.clearRetainingCapacity();
    try dq.putBytes(epoch);
    try dq.putU64(0);
    try t.expectEqual(api.Status.OK, apiGetContactsDelta(&app, dq.items(), &ds));
    var last_kind: u8 = 0xFF;
    {
        var rr = api.Reader.init(ds.items());
        try t.expectEqualSlices(u8, epoch, try rr.readBytes(16));
        const to_rev = try rr.readU64();
        try t.expectEqual(rev0, to_rev);
        const n = try rr.readU32();
        try t.expect(n > 0);
        var i: u32 = 0;
        while (i < n) : (i += 1) {
            const r = try rr.readU64();
            const kind = try rr.readU8();
            const c = try rr.readU32();
            try t.expect(r > 0); // ревизии плотные, от 1
            try t.expectEqual(@as(u32, 1), c);
            if (kind == @backingInt(api.DeltaChange.upsert)) {
                // за заголовком — полный contact_view
                _ = try rr.readU32();
                _ = try rr.readU8();
                _ = try rr.readI64();
                _ = try rr.readStr16();
                _ = try rr.readBytes(16);
                _ = try rr.readU8();
                _ = try rr.readU32();
                _ = try rr.readU16();
                _ = try rr.readU32();
            }
            last_kind = kind;
        }
        try t.expect(!rr.hasMore());
        try t.expectEqual(@as(u8, @backingInt(api.DeltaChange.upsert)), last_kind);
    }
    // чужой epoch / ревизия из будущего — пересинхрон
    dq.list.clearRetainingCapacity();
    try dq.putBytes(&@as([16]u8, @splat(9)));
    try dq.putU64(0);
    try t.expectEqual(api.Status.RESYNC_REQUIRED, apiGetContactsDelta(&app, dq.items(), &ds));
    dq.list.clearRetainingCapacity();
    try dq.putBytes(epoch);
    try dq.putU64(rev0 + 1);
    try t.expectEqual(api.Status.BAD_ARGS, apiGetContactsDelta(&app, dq.items(), &ds));

    // GET_HISTORY_PAGE: строгий порядок (ts, msg_id), курсор, has_more
    var ids: [5][16]u8 = undefined;
    for (&ids, 0..) |*m, i| {
        m.* = @splat(@truncate(i + 1));
        persistMsg(&app, 1, true, m.*, null, true, 1000 + @as(i64, @intCast(i)), "msg", &.{});
    }
    var pq = api.Writer.init(alloc);
    defer pq.deinit();
    try pq.putU32(1);
    try pq.putU8(0); // без курсора: хвост
    try pq.putU64(0);
    try pq.putBytes(&@as([16]u8, @splat(0)));
    try pq.putU16(2);
    var ps = api.Writer.init(alloc);
    defer ps.deinit();
    try t.expectEqual(api.Status.OK, apiGetHistoryPage(&app, pq.items(), &ps));
    var next_ts: u64 = 0;
    var next_id: [16]u8 = @splat(0);
    {
        var rr = api.Reader.init(ps.items());
        const has_more = try rr.readU8();
        next_ts = try rr.readU64();
        const nid = try rr.readBytes(16);
        next_id = nid[0..16].*;
        const n = try rr.readU32();
        try t.expect(has_more != 0);
        try t.expectEqual(@as(u32, 2), n);
        // последние две записи: ts 1003/1004
        var prev_ts: u64 = std.math.maxInt(u64);
        var i: u32 = 0;
        while (i < n) : (i += 1) {
            _ = try rr.readU8(); // flags
            const mids = try rr.readBytes(16);
            const mid = mids[0..16].*;
            const ts = try rr.readU64();
            _ = try rr.readStr16();
            _ = try rr.readU8(); // счётчик entities
            try t.expect(ts < prev_ts); // убывание внутри страницы
            prev_ts = ts;
            if (i == 0) try t.expectEqual(@as(u64, 1004), ts);
            if (i == 1) try t.expectEqualSlices(u8, &ids[3], &mid);
        }
        try t.expect(!rr.hasMore());
    }
    try t.expectEqual(@as(u64, 1003), next_ts);
    // вторая страница тем же курсором — продолжение без дублей
    pq.list.clearRetainingCapacity();
    try pq.putU32(1);
    try pq.putU8(1);
    try pq.putU64(next_ts);
    try pq.putBytes(&next_id);
    try pq.putU16(2);
    ps.list.clearRetainingCapacity();
    try t.expectEqual(api.Status.OK, apiGetHistoryPage(&app, pq.items(), &ps));
    {
        var rr = api.Reader.init(ps.items());
        const has_more = try rr.readU8();
        _ = try rr.readU64();
        _ = try rr.readBytes(16);
        const n = try rr.readU32();
        try t.expect(has_more != 0);
        try t.expectEqual(@as(u32, 2), n);
        _ = try rr.readU8();
        var mid: [16]u8 = undefined;
        @memcpy(&mid, try rr.readBytes(16));
        try t.expectEqualSlices(u8, &ids[2], &mid); // строго старее курсора
    }
    // лимит: 0 → 30 по умолчанию не роняет, 201 → TOO_BIG
    pq.list.clearRetainingCapacity();
    try pq.putU32(1);
    try pq.putU8(0);
    try pq.putU64(0);
    try pq.putBytes(&@as([16]u8, @splat(0)));
    try pq.putU16(201);
    try t.expectEqual(api.Status.TOO_BIG, apiGetHistoryPage(&app, pq.items(), &ps));
    pq.list.clearRetainingCapacity();
    try pq.putU32(99);
    try pq.putU8(0);
    try pq.putU64(0);
    try pq.putBytes(&@as([16]u8, @splat(0)));
    try pq.putU16(5);
    try t.expectEqual(api.Status.NO_CONTACT, apiGetHistoryPage(&app, pq.items(), &ps));

    // DELETE_CHAT → REMOVED-ревизия в дельте
    var dc = api.Writer.init(alloc);
    defer dc.deinit();
    try dc.putU32(1);
    try t.expectEqual(api.Status.OK, apiDeleteChat(&app, dc.items(), &ps));
    dq.list.clearRetainingCapacity();
    try dq.putBytes(epoch);
    try dq.putU64(rev0);
    ds.list.clearRetainingCapacity();
    try t.expectEqual(api.Status.OK, apiGetContactsDelta(&app, dq.items(), &ds));
    {
        var rr = api.Reader.init(ds.items());
        _ = try rr.readBytes(16);
        _ = try rr.readU64();
        const n = try rr.readU32();
        try t.expect(n > 0);
        var i: u32 = 0;
        while (i < n - 1) : (i += 1) {
            _ = try rr.readU64();
            const kind = try rr.readU8();
            const c = try rr.readU32();
            _ = c;
            if (kind == @backingInt(api.DeltaChange.upsert)) {
                _ = try rr.readU32();
                _ = try rr.readU8();
                _ = try rr.readI64();
                _ = try rr.readStr16();
                _ = try rr.readBytes(16);
                _ = try rr.readU8();
                _ = try rr.readU32();
                _ = try rr.readU16();
                _ = try rr.readU32();
            }
        }
        _ = try rr.readU64();
        const kind = try rr.readU8();
        const c = try rr.readU32();
        try t.expectEqual(@as(u8, @backingInt(api.DeltaChange.removed)), kind);
        try t.expectEqual(@as(u32, 1), c);
        try t.expect(!rr.hasMore());
    }

    // CREATE_INVITE_EX: discovery → v2-код + invite_id; state по нему
    var cq = api.Writer.init(alloc);
    defer cq.deinit();
    try cq.putU8(@backingInt(api.InviteExMode.discovery));
    try cq.putStr16("host");
    try cq.putStr16("");
    try cq.putStr16("");
    var cs = api.Writer.init(alloc);
    defer cs.deinit();
    try t.expectEqual(api.Status.OK, apiCreateInviteEx(&app, cq.items(), &cs));
    var invite_id: [16]u8 = @splat(0);
    {
        var rr = api.Reader.init(cs.items());
        const ic = try rr.readStr16();
        try t.expect(std.mem.startsWith(u8, ic, invite_mod.v2_prefix));
        @memcpy(&invite_id, try rr.readBytes(16));
        try t.expect(!rr.hasMore());
    }
    var iq = api.Writer.init(alloc);
    defer iq.deinit();
    try iq.putBytes(&invite_id);
    var is = api.Writer.init(alloc);
    defer is.deinit();
    try t.expectEqual(api.Status.OK, apiGetInviteState(&app, iq.items(), &is));
    {
        var rr = api.Reader.init(is.items());
        try t.expectEqual(@as(u8, @backingInt(api.InviteState.active)), try rr.readU8());
        try t.expectEqual(@as(u32, 0), try rr.readU32());
        try t.expectEqual(@as(i64, 0), try rr.readI64());
        try t.expect(!rr.hasMore());
    }
    // случайный идентификатор — NOT_FOUND
    var iq2 = api.Writer.init(alloc);
    defer iq2.deinit();
    try iq2.putBytes(&@as([16]u8, @splat(0xEE)));
    try t.expectEqual(api.Status.NOT_FOUND, apiGetInviteState(&app, iq2.items(), &is));
    // валидация режимов: прямой без адреса / discovery с адресом / битый mode
    cq.list.clearRetainingCapacity();
    try cq.putU8(@backingInt(api.InviteExMode.direct));
    try cq.putStr16("h");
    try cq.putStr16("");
    try cq.putStr16("");
    try t.expectEqual(api.Status.BAD_ARGS, apiCreateInviteEx(&app, cq.items(), &cs));
    cq.list.clearRetainingCapacity();
    try cq.putU8(9);
    try t.expectEqual(api.Status.BAD_ARGS, apiCreateInviteEx(&app, cq.items(), &cs));
    cq.list.clearRetainingCapacity();
    try cq.putU8(@backingInt(api.InviteExMode.discovery));
    try cq.putStr16("h");
    try cq.putStr16("10.0.0.1:7777");
    try cq.putStr16("");
    try t.expectEqual(api.Status.BAD_ARGS, apiCreateInviteEx(&app, cq.items(), &cs));

    // GET_REACHABLE_ENDPOINTS: не слушаем — пусто (не ошибка)
    var es = api.Writer.init(alloc);
    defer es.deinit();
    try t.expectEqual(api.Status.OK, apiGetReachableEndpoints(&app, &.{}, &es));
    try t.expectEqual(@as(usize, 1), es.items().len);
    try t.expectEqual(@as(u8, 0), es.items()[0]);
}

test "2.7.0: GET_CONTACTS_DELTA окно и RESYNC за границей кольца" {
    const t = std.testing;
    const alloc = t.allocator;
    const seed: [32]u8 = @splat(0x66);
    var id = try identity.Identity.fromSeed(seed);
    defer id.deinit();
    var eng = engine_mod.Engine.init(alloc, t.io, id, .{ .ctx = undefined });
    defer eng.deinit();
    var app = App{
        .alloc = alloc,
        .io = t.io,
        .id = &id,
        .eng = &eng,
        .log = null,
        .hb = std.AutoHashMap(i64, hb.State).init(alloc),
        .sess_ctx = std.AutoHashMap(i64, *SessCtx).init(alloc),
        .provisioned = true,
        .no_network = true,
    };
    defer app.hb.deinit();
    defer app.sess_ctx.deinit();

    // кольцо фиксированного размера: известное число ревизий > cap
    app.contacts_epoch = @splat(7);
    for (0..contact_ring_cap + 10) |_| {
        _ = app.eng.addContact("x", @as([64]u8, @splat(0xCD))) catch unreachable;
        // ringAppend без контакта не имеет смысла: используем реальный бамп
        const cid: i64 = @intCast(app.eng.contacts.items.len);
        bumpContactLocked(&app, cid);
    }
    const total_rev = app.contacts_rev;
    try t.expectEqual(@as(u64, contact_ring_cap + 10), total_rev);
    // самая старая доступная ревизия = rev - cap + 1
    {
        var dq = api.Writer.init(alloc);
        defer dq.deinit();
        try dq.putBytes(&app.contacts_epoch);
        try dq.putU64(total_rev - @as(u64, contact_ring_cap));
        var ds = api.Writer.init(alloc);
        defer ds.deinit();
        try t.expectEqual(api.Status.OK, apiGetContactsDelta(&app, dq.items(), &ds));
        var rr = api.Reader.init(ds.items());
        _ = try rr.readBytes(16);
        try t.expectEqual(total_rev, try rr.readU64());
        try t.expectEqual(@as(u32, contact_ring_cap), try rr.readU32());
    }
    // за границей окна — RESYNC_REQUIRED
    var dq = api.Writer.init(alloc);
    defer dq.deinit();
    try dq.putBytes(&app.contacts_epoch);
    try dq.putU64(total_rev - @as(u64, contact_ring_cap) - 1);
    var ds = api.Writer.init(alloc);
    defer ds.deinit();
    try t.expectEqual(api.Status.RESYNC_REQUIRED, apiGetContactsDelta(&app, dq.items(), &ds));
}
