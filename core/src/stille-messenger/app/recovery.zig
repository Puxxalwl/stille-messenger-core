//! Recovery-пакет профиля: сборка из живого приложения (createBackup) и
//! применение к непровиженному демону (applyBackup). Криптография и формат
//! блоба — crypto/recovery.zig; сценарий для GUI — CORE-API.md §4.10 и
//! CLIENT_RULES.md в корне репозитория.
//!
//! Пакет — восстановление ДОСТУПА, не репликация: сид личности, имя,
//! аватар, конфигурация, контакты (с маршрутами) и блокировки. История,
//! файлы, закрепления и клиентская БД НЕ входят: новое устройство начинает
//! с пустой историей, но собеседники видят того же человека (тот же
//! bundle) и пишут в те же чаты.
//!
//! Точки атомарности применения: все записи лога дописываются ДО
//! сохранения сида на диск; сид — точка фиксации (после неё профиль
//! провижен даже при падении процесса: рестарт поднимет его из
//! сида и лога). Неудача раньше — лог удаляется, профиль остаётся
//! пустым, повторная попытка возможна. Секреты (сид, unlock-секрет,
//! производный ключ) в ядре не задерживаются: обнуляются на выходе.

const std = @import("std");
const stille_messenger = @import("stille-messenger");
const recovery = stille_messenger.crypto.recovery;
const identity_mod = stille_messenger.crypto.identity;
const engine_mod = stille_messenger.core.engine;
const store_mod = stille_messenger.store.log;
const sync_mod = stille_messenger.app.sync;
const config_mod = stille_messenger.app.config;
const hb = stille_messenger.net.heartbeat;
const app_mod = @import("app.zig");
const receive = @import("receive.zig");
const paths = @import("paths.zig");
const persist = @import("persist.zig");
const sync_apply = @import("sync_apply.zig");
const api = @import("api.zig");

/// Ошибки применения пакета (маппятся в статусы API вызывающим).
pub const ApplyError = error{
    /// Профиль уже провижен (RESTORE требует пустой).
    AlreadyProvisioned,
    /// Сид пакета не выводится в личность или конфигурация не декодируется.
    BadRecovery,
    /// Файловая/аллокационная неудача.
    Internal,
};

/// Результат сборки пакета.
pub const CreateResult = union(enum) {
    /// Запечатанный блоб (owned, аллокатор приложения).
    ok: []u8,
    /// Статус ошибки для ответа клиенту.
    err: api.Status,
};

/// Собрать и запечатать recovery-пакет текущего профиля.
/// ВЫЗЫВАТЬ ПОД app.mu на провиженном профиле; nonce — снаружи
/// (io.random до взятия лока: io под спин-локом не трогаем).
///
/// Сид читается с диска (0600-файл): в памяти ядра сид не удерживается,
/// поэтому он доступен только из файла. Поля заимствуются из состояния
/// приложения на время seal; копии — только во временном открытом тексте.
pub fn createBackup(app: *app_mod.App, unlock_secret: *const [recovery.secret_length]u8, nonce: [recovery.nonce_length]u8) CreateResult {
    if (!app.provisioned or app.log == null) return .{ .err = .NOT_INITIALIZED };

    var seed: [32]u8 = paths.loadSeed(app.io, paths.appHomeDir(app)) catch |e| switch (e) {
        error.FileNotFound => return .{ .err = .NOT_INITIALIZED },
        else => return .{ .err = .INTERNAL },
    };
    defer std.crypto.secureZero(u8, &seed);

    // контакты: записи формата лога из текущего состояния (имя, bundle,
    // последний адрес, relay-адрес, роль линка). Удалённые чаты не входят.
    const total = app.eng.contacts.items.len;
    if (total > recovery.max_contacts) return .{ .err = .TOO_BIG };
    const contacts_buf = app.alloc.alloc(u8, total * recovery.max_contact_rec) catch return .{ .err = .INTERNAL };
    defer app.alloc.free(contacts_buf);
    const contacts = app.alloc.alloc([]const u8, total) catch return .{ .err = .INTERNAL };
    defer app.alloc.free(contacts);
    const blocks_buf = app.alloc.alloc(u8, total * recovery.block_rec_len) catch return .{ .err = .INTERNAL };
    defer app.alloc.free(blocks_buf);
    const blocks = app.alloc.alloc([]const u8, total) catch return .{ .err = .INTERNAL };
    defer app.alloc.free(blocks);

    var n_contacts: usize = 0;
    var n_blocks: usize = 0;
    for (app.eng.contacts.items, 0..) |*c, i| {
        if (c.deleted) continue;
        var abuf: [72]u8 = undefined;
        const addr_ = c.addr(&abuf);
        const cid: i64 = @intCast(i + 1);
        const relay = app.contact_relays.get(cid) orelse "";

        var rec: [recovery.max_contact_rec]u8 = undefined;
        const rn = persist.encodeContactRecord(&rec, c.getName(), c.bundle, addr_, relay, c.dev_role);
        const dst = contacts_buf[n_contacts * recovery.max_contact_rec ..][0..rn];
        @memcpy(dst, rec[0..rn]);
        contacts[n_contacts] = dst;
        n_contacts += 1;

        if (c.blocked) {
            const bdst = blocks_buf[n_blocks * recovery.block_rec_len ..][0..recovery.block_rec_len];
            @memcpy(bdst[0..64], &c.bundle);
            bdst[64] = 1;
            blocks[n_blocks] = bdst;
            n_blocks += 1;
        }
    }

    // аватар: байты из кэша (kind avatar лога); пусто — аватара нет
    const avatar: []const u8 = blk: {
        const id = app.eng.my_avatar_id;
        if (std.mem.eql(u8, &id, &@as([16]u8, @splat(0)))) break :blk "";
        break :blk app.avatars.get(id) orelse "";
    };

    // конфигурация: текущий blob (server_mode/relay-адреса переживают
    // восстановление — иначе контакты через релей не достучались бы)
    var cfg_buf: [recovery.max_cfg]u8 = undefined;
    const cfg = app.cfg.encode(&cfg_buf) catch return .{ .err = .INTERNAL };

    const plain = recovery.Plain{
        .seed = seed,
        .name = app.eng.myName(),
        .avatar = avatar,
        .cfg = cfg,
        .contacts = contacts[0..n_contacts],
        .blocks = blocks[0..n_blocks],
    };
    const blob = recovery.seal(app.alloc, plain, unlock_secret, nonce) catch |e| switch (e) {
        error.TooBig => return .{ .err = .TOO_BIG },
        error.BadFormat, error.Tampered, error.OutOfMemory => return .{ .err = .INTERNAL },
    };
    return .{ .ok = blob };
}

/// Применить распакованный пакет к непровиженному профилю.
/// ВЫЗЫВАТЬ ПОД app.mu; app.provisioned обязан быть false. Порядок:
/// открыть лог → дописать записи → сохранить сид (фиксация) → подменить
/// личность на месте → перезарядить профиль. Неудача до фиксации —
/// созданный лог закрывается и удаляется, профиль остаётся пустым.
pub fn applyBackup(app: *app_mod.App, backup: *recovery.Backup) ApplyError!void {
    if (app.provisioned) return error.AlreadyProvisioned;
    // сид на диске при непровиженном демоне (init после старта в режиме
    // восстановления): на диске УЖЕ есть профиль — не затираем молча;
    // GUI должен перезапустить демон или явно сбросить профиль
    disk_seed: {
        var existing = paths.loadSeed(app.io, paths.appHomeDir(app)) catch |e| switch (e) {
            error.FileNotFound => break :disk_seed, // пустой профиль
            else => return error.Internal, // нечитаемый сид — конфликт
        };
        defer std.crypto.secureZero(u8, &existing);
        return error.AlreadyProvisioned;
    }
    // личность обязана выводиться из сида пакета
    const new_id = identity_mod.Identity.fromSeed(backup.seed) catch return error.BadRecovery;

    var path_buf: [512]u8 = undefined;
    const store_path = std.fmt.bufPrint(&path_buf, "{s}/{s}/zig-log", .{ paths.appHomeDir(app), paths.data_dir_name }) catch return error.Internal;

    const lp = app.alloc.create(store_mod.Log) catch return error.Internal;
    var have_log = false; // lp.* инициализирован (файл открыт)
    var committed = false; // лог закреплён за профилем (сид сохранён)
    defer {
        if (have_log and !committed) {
            lp.deinit();
            std.Io.Dir.deleteFileAbsolute(app.io, store_path) catch {};
        }
        if (!committed) app.alloc.destroy(lp);
    }

    lp.* = openFreshLog(app, store_path, &backup.seed) catch return error.Internal;
    have_log = true;

    // записи профиля: контакты и блокировки (формат лога как есть),
    // имя (set:2), аватар (set:1 + кэш kind avatar), конфигурация (cfg)
    for (backup.contacts) |rec| {
        _ = lp.append(.contact, rec) catch return error.Internal;
    }
    for (backup.blocks) |rec| {
        _ = lp.append(.block, rec) catch return error.Internal;
    }
    if (backup.name.len > 0) {
        var nb: [1 + recovery.max_name]u8 = undefined;
        nb[0] = 2;
        @memcpy(nb[1 .. 1 + backup.name.len], backup.name);
        _ = lp.append(.set, nb[0 .. 1 + backup.name.len]) catch return error.Internal;
    }
    if (backup.avatar.len > 0) {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(backup.avatar, &digest, .{});
        const avatar_id = digest[0..16].*;
        var rb: [17]u8 = undefined;
        rb[0] = 1;
        @memcpy(rb[1..17], &avatar_id);
        _ = lp.append(.set, &rb) catch return error.Internal;
        var ab: [18 + recovery.max_avatar]u8 = undefined;
        @memcpy(ab[0..16], &avatar_id);
        std.mem.writeInt(u16, ab[16..18], @intCast(backup.avatar.len), .little);
        @memcpy(ab[18 .. 18 + backup.avatar.len], backup.avatar);
        _ = lp.append(.avatar, ab[0 .. 18 + backup.avatar.len]) catch return error.Internal;
    }
    if (backup.cfg.len > 0) {
        // конфигурация обязана декодироваться ядром этой же версии
        var probe = config_mod.Config{};
        probe.decode(backup.cfg) catch return error.BadRecovery;
        _ = lp.append(.cfg, backup.cfg) catch return error.Internal;
    }

    // ТОЧКА ФИКСАЦИИ: сид на диск (0600, эксклюзивно). После неё профиль
    // провижен даже при падении процесса — рестарт поднимет его сам.
    paths.saveSeed(app.io, paths.appHomeDir(app), backup.seed) catch |e| switch (e) {
        // гонка: сид появился после проверки выше — тот же конфликт
        error.PathAlreadyExists => return error.AlreadyProvisioned,
        else => return error.Internal,
    };
    committed = true;

    // подмена личности НА МЕСТЕ: указатели приложения/движка валидны,
    // сессий нет (непровижненный демон сети не поднимал)
    app.id.deinit();
    app.id.* = new_id;
    app.eng.id.deinit();
    app.eng.id = new_id;

    // синхронизация устройств: ключ от нового сида
    app.sync.deinit();
    app.sync = sync_mod.Sync.init(app.alloc, &backup.seed);
    app.sync.tr_ctx = app;
    app.sync.tr_fn = sync_apply.syncTranslateBundle;

    // перезагрузка профиля из лога (контакты, блокировки, настройки,
    // аватар-кэш, конфигурация; история пуста — её в пакете нет)
    app.log = lp;
    persist.loadContacts(app);
    app.provisioned = true;
}

/// Открыть лог для восстановления: непровижненный профиль ничем не
/// владеет, поэтому существующий файл — нечитаемый сирота (без сида его
/// никто не мог записать валидно) или хвост прошлой неудачной попытки
/// (тот же сид — записи дублировались бы); в обоих случаях файл
/// заменяется. Пустой новый файл проходит как есть.
fn openFreshLog(app: *app_mod.App, path: []const u8, seed: *const [32]u8) store_mod.Error!store_mod.Log {
    var log = store_mod.Log.open(app.alloc, path, seed) catch |e| switch (e) {
        // битый/чужой файл: заменить (владельца у него нет)
        error.Corrupt => {
            std.Io.Dir.deleteFileAbsolute(app.io, path) catch return e;
            return store_mod.Log.open(app.alloc, path, seed);
        },
        else => return e,
    };
    if (log.index.items.len != 0) {
        // хвост прошлой попытки того же сида: пересоздать без дублей
        log.deinit();
        std.Io.Dir.deleteFileAbsolute(app.io, path) catch return error.InputOutput;
        log = try store_mod.Log.open(app.alloc, path, seed);
        if (log.index.items.len != 0) return error.Corrupt;
    }
    return log;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

/// Приложение с настоящим логом в tmp-каталоге. initAt вызывается на
/// УЖЕ размещённом значении (адреса полей стабильны: App держит указатели
/// на id/eng/log этого же объекта).
const TestApp = struct {
    id: identity_mod.Identity,
    eng: engine_mod.Engine,
    /// Лог собственного профиля (только провижненный случай).
    log: ?store_mod.Log = null,
    app: app_mod.App,
    home: []const u8,
    dir: testing.TmpDir,

    /// provisioned: лог открывается по {home}/.stille-messenger/zig-log.
    /// write_seed: файл сида пишется (как после init CLI).
    fn initAt(self: *TestApp, alloc: std.mem.Allocator, io: std.Io, seed: [32]u8, provisioned: bool, write_seed: bool) !void {
        self.dir = testing.tmpDir(.{});
        errdefer self.dir.cleanup();
        self.log = null; // непровижненный путь лога не открывает
        var dir_buf: [4096]u8 = undefined;
        const real_len = try self.dir.dir.realPath(io, &dir_buf);
        self.home = try alloc.dupe(u8, dir_buf[0..real_len]);
        errdefer alloc.free(self.home);

        // .stille-messenger (0700): сид/лог живут здесь
        var pb: [512]u8 = undefined;
        const data_dir = try std.fmt.bufPrint(&pb, "{s}/{s}", .{ self.home, paths.data_dir_name });
        std.Io.Dir.createDirAbsolute(io, data_dir, @fromBackingInt(@intCast(0o700))) catch {};

        if (write_seed) {
            var sb: [512]u8 = undefined;
            const seed_path = try std.fmt.bufPrint(&sb, "{s}/{s}/zig-seed", .{ self.home, paths.data_dir_name });
            const f = try std.Io.Dir.createFileAbsolute(io, seed_path, .{ .exclusive = true });
            defer f.close(io);
            try f.writePositionalAll(io, &seed, 0);
            f.setPermissions(io, .fromMode(0o600)) catch {};
        }

        self.id = try identity_mod.Identity.fromSeed(seed);
        errdefer self.id.deinit();
        self.eng = engine_mod.Engine.init(alloc, io, self.id, .{ .ctx = undefined });
        errdefer self.eng.deinit();

        if (provisioned) {
            var lb: [512]u8 = undefined;
            const log_path = try std.fmt.bufPrint(&lb, "{s}/{s}/zig-log", .{ self.home, paths.data_dir_name });
            self.log = try store_mod.Log.open(alloc, log_path, &seed);
        }

        self.app = .{
            .session_bind = receive.bindSession,
            .session_env_in = receive.envIn,
            .session_on_closed = receive.onClosed,
            .alloc = alloc,
            .io = io,
            .id = &self.id,
            .eng = &self.eng,
            .log = if (self.log) |*l| l else null,
            .hb = std.AutoHashMap(i64, hb.State).init(alloc),
            .sess_ctx = std.AutoHashMap(i64, *app_mod.SessCtx).init(alloc),
            .provisioned = provisioned,
            // тесты: loadContacts без сетевых потоков присутствия
            .no_network = true,
        };
        self.app.home_len = @min(self.home.len, paths.app_home_max);
        @memcpy(self.app.home_buf[0..self.app.home_len], self.home[0..self.app.home_len]);
        self.app.sync = sync_mod.Sync.init(alloc, &seed);
        self.app.sync.tr_ctx = &self.app;
        self.app.sync.tr_fn = sync_apply.syncTranslateBundle;
    }

    fn deinit(self: *TestApp, alloc: std.mem.Allocator) void {
        self.app.sync.deinit();
        self.app.hb.deinit();
        self.app.sess_ctx.deinit();
        // аватары/релеи могли появиться при загрузке профиля
        var it = self.app.avatars.valueIterator();
        while (it.next()) |data| alloc.free(data.*);
        self.app.avatars.deinit(alloc);
        var it2 = self.app.contact_relays.valueIterator();
        while (it2.next()) |ra| alloc.free(ra.*);
        self.app.contact_relays.deinit(alloc);
        // лог: собственный (провижненный) или heap-лог applyBackup
        if (self.app.log) |lp| {
            lp.deinit();
            if (self.log == null or lp != &self.log.?) {
                alloc.destroy(lp);
            }
        } else if (self.log) |*l| {
            l.deinit();
        }
        self.eng.deinit();
        self.id.deinit();
        alloc.free(self.home);
        self.dir.cleanup();
    }
};

test "recovery app: create -> restore roundtrip на свежем демоне" {
    const alloc = testing.allocator;
    const seed: [32]u8 = @splat(0x73);
    const secret: [32]u8 = @splat(0x42);
    const nonce: [recovery.nonce_length]u8 = @splat(0x0F);

    // провижненный профиль: сид на диске, лог, имя, аватар, контакты, блок
    var src: TestApp = undefined;
    try src.initAt(alloc, testing.io, seed, true, true);
    defer src.deinit(alloc);
    {
        const name = "stille-user";
        const avatar: [32]u8 = @splat(0x91);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&avatar, &digest, .{});
        const avatar_id = digest[0..16].*;
        src.eng.setMyProfile(name, avatar_id);
        const avatar_copy = try alloc.dupe(u8, &avatar);
        try src.app.avatars.put(alloc, avatar_id, avatar_copy);
        var rb: [17]u8 = undefined;
        rb[0] = 1;
        @memcpy(rb[1..17], &avatar_id);
        _ = try src.log.?.append(.set, &rb);
        var nb: [1 + 32]u8 = undefined;
        nb[0] = 2;
        @memcpy(nb[1 .. 1 + name.len], name);
        _ = try src.log.?.append(.set, nb[0 .. 1 + name.len]);
        var ab: [18 + 32]u8 = undefined;
        @memcpy(ab[0..16], &avatar_id);
        std.mem.writeInt(u16, ab[16..18], 32, .little);
        @memcpy(ab[18..50], &avatar);
        _ = try src.log.?.append(.avatar, ab[0..50]);

        // контакт с адресом + relay; заблокированный контакт
        var peer = try identity_mod.Identity.fromSeed(@splat(0x31));
        defer peer.deinit();
        var rec: [recovery.max_contact_rec]u8 = undefined;
        const rn = persist.encodeContactRecord(&rec, "bob", peer.bundle(), "10.1.2.3:7777", "relay.example:9000", 0);
        _ = try src.log.?.append(.contact, rec[0..rn]);
        _ = try src.eng.addContact("bob", peer.bundle());
        src.eng.contacts.items[0].setAddr("10.1.2.3", 7777);
        const relay_copy = try alloc.dupe(u8, "relay.example:9000");
        try src.app.contact_relays.put(alloc, 1, relay_copy);

        var foe = try identity_mod.Identity.fromSeed(@splat(0x32));
        defer foe.deinit();
        var rec2: [recovery.max_contact_rec]u8 = undefined;
        const rn2 = persist.encodeContactRecord(&rec2, "foe", foe.bundle(), null, null, 0);
        _ = try src.log.?.append(.contact, rec2[0..rn2]);
        _ = try src.eng.addContact("foe", foe.bundle());
        src.eng.contacts.items[1].blocked = true;
        var bb: [65]u8 = @splat(0);
        @memcpy(bb[0..64], &foe.bundle());
        bb[64] = 1;
        _ = try src.log.?.append(.block, &bb);

        // конфигурация не по умолчанию
        src.app.cfg.server_mode = true;
        try src.app.cfg.setServerAddr("vps.example:9000");
    }

    // сборка пакета
    const res = createBackup(&src.app, &secret, nonce);
    const blob = switch (res) {
        .ok => |b| b,
        .err => |st| {
            std.debug.print("createBackup error: {s}\n", .{@tagName(st)});
            return error.TestUnexpectedResult;
        },
    };
    defer alloc.free(blob);
    try testing.expect(blob.len >= recovery.min_backup_len);

    // свежий демон без сида: восстановление
    var dst: TestApp = undefined;
    try dst.initAt(alloc, testing.io, @splat(0), false, false);
    defer dst.deinit(alloc);
    var backup = try recovery.open(alloc, blob, &secret);
    defer backup.deinit(alloc);
    try applyBackup(&dst.app, &backup);
    try testing.expect(dst.app.provisioned);
    try testing.expect(dst.app.log != null);

    // тот же bundle/личность (обе копии), имя, контакты, блокировка, конфиг
    try testing.expectEqualSlices(u8, &src.id.bundle(), &dst.app.id.bundle());
    try testing.expectEqualSlices(u8, &dst.app.id.bundle(), &dst.eng.id.bundle());
    try testing.expectEqualStrings("stille-user", dst.app.eng.myName());
    try testing.expectEqual(@as(usize, 2), dst.eng.contacts.items.len);
    try testing.expectEqualStrings("bob", dst.eng.contacts.items[0].getName());
    try testing.expectEqualSlices(u8, &src.eng.contacts.items[0].bundle, &dst.eng.contacts.items[0].bundle);
    try testing.expect(dst.eng.contacts.items[0].blocked == false);
    try testing.expect(dst.eng.contacts.items[1].blocked == true);
    // прямые адреса и relay-хвост пережили восстановление
    const c0 = &dst.eng.contacts.items[0];
    try testing.expectEqualStrings("10.1.2.3", c0.addr_buf[0..c0.addr_len]);
    try testing.expectEqual(@as(u16, 7777), c0.addr_port);
    try testing.expect(dst.app.contact_relays.get(1) != null);
    // конфигурация применилась
    try testing.expect(dst.app.cfg.server_mode == true);
    try testing.expectEqualStrings("vps.example:9000", dst.app.cfg.serverAddr());
    // аватар в кэше и id совпадают
    try testing.expect(dst.app.avatars.get(dst.eng.my_avatar_id) != null);
    try testing.expectEqualSlices(u8, &src.eng.my_avatar_id, &dst.eng.my_avatar_id);
    // сид записан на диск: рестарт поднимет тот же профиль
    const restored_seed = try paths.loadSeed(dst.app.io, dst.home);
    try testing.expectEqualSlices(u8, &seed, &restored_seed);
    // история пуста (в пакете её нет)
    try testing.expectEqual(@as(usize, 0), dst.app.hist.items.len);
}

test "recovery app: create требует провижненный профиль и сид на диске" {
    const alloc = testing.allocator;
    const secret: [32]u8 = @splat(1);
    const nonce: [recovery.nonce_length]u8 = @splat(0);

    var unprov: TestApp = undefined;
    try unprov.initAt(alloc, testing.io, @splat(0), false, false);
    defer unprov.deinit(alloc);
    const res = createBackup(&unprov.app, &secret, nonce);
    try testing.expectEqual(api.Status.NOT_INITIALIZED, res.err);

    // провижненный, но файл сида пропал (удалили при жизни демона)
    var prov: TestApp = undefined;
    try prov.initAt(alloc, testing.io, @splat(0x55), true, false);
    defer prov.deinit(alloc);
    const res2 = createBackup(&prov.app, &secret, nonce);
    try testing.expectEqual(api.Status.NOT_INITIALIZED, res2.err);
}

test "recovery app: apply требует пустой профиль" {
    const alloc = testing.allocator;
    const secret: [32]u8 = @splat(0x42);

    var src: TestApp = undefined;
    try src.initAt(alloc, testing.io, @splat(0x73), true, true);
    defer src.deinit(alloc);
    src.eng.setMyProfile("a", src.eng.my_avatar_id);
    const res = createBackup(&src.app, &secret, @splat(0));
    const blob = res.ok;
    defer alloc.free(blob);

    var prov: TestApp = undefined;
    try prov.initAt(alloc, testing.io, @splat(0x11), true, true);
    defer prov.deinit(alloc);
    var backup = try recovery.open(alloc, blob, &secret);
    defer backup.deinit(alloc);
    try testing.expectError(error.AlreadyProvisioned, applyBackup(&prov.app, &backup));
    // профиль не тронут
    try testing.expectEqualSlices(u8, &prov.id.bundle(), &prov.app.id.bundle());
}

test "recovery app: неудача до фиксации и повторная попытка без дублей" {
    const alloc = testing.allocator;
    const secret: [32]u8 = @splat(0x42);

    var src: TestApp = undefined;
    try src.initAt(alloc, testing.io, @splat(0x73), true, true);
    defer src.deinit(alloc);
    var peer = try identity_mod.Identity.fromSeed(@splat(0x31));
    defer peer.deinit();
    _ = try src.eng.addContact("bob", peer.bundle());
    var rec: [recovery.max_contact_rec]u8 = undefined;
    const rn = persist.encodeContactRecord(&rec, "bob", peer.bundle(), null, null, 0);
    _ = try src.log.?.append(.contact, rec[0..rn]);

    const res = createBackup(&src.app, &secret, @splat(0));
    const blob = res.ok;
    defer alloc.free(blob);

    // пакет-саботажник: AEAD-валиден (распаковывается тем же секретом),
    // но конфигурация не декодируется ядром — отказ ПОСЛЕ записи
    // контактов в лог, но ДО фиксации сида
    const bad_cfg = [_]u8{ 0xFF, 0xFF };
    const contact_recs = [_][]const u8{rec[0..rn]};
    const bad_plain = recovery.Plain{
        .seed = @splat(0x73),
        .name = "bob",
        .avatar = "",
        .cfg = &bad_cfg,
        .contacts = contact_recs[0..],
        .blocks = &.{},
    };
    const bad_blob = recovery.seal(alloc, bad_plain, &secret, @splat(0)) catch unreachable;
    defer alloc.free(bad_blob);

    var dst: TestApp = undefined;
    try dst.initAt(alloc, testing.io, @splat(0), false, false);
    defer dst.deinit(alloc);
    var bad_backup = try recovery.open(alloc, bad_blob, &secret);
    defer bad_backup.deinit(alloc);
    try testing.expectError(error.BadRecovery, applyBackup(&dst.app, &bad_backup));
    // профиль не тронут: лог-сирота удалён, сид не записан
    try testing.expect(!dst.app.provisioned);
    try testing.expect(dst.app.log == null);

    // повторная попытка (как после перезапуска демона): валидный пакет
    // применяется в чистый лог, записи не дублируются
    var backup2 = try recovery.open(alloc, blob, &secret);
    defer backup2.deinit(alloc);
    try applyBackup(&dst.app, &backup2);
    try testing.expectEqual(@as(usize, 1), dst.eng.contacts.items.len);
    try testing.expectEqualStrings("bob", dst.eng.contacts.items[0].getName());
}

test "recovery app: сид на диске при непровиженном демоне — конфликт" {
    const alloc = testing.allocator;
    const secret: [32]u8 = @splat(0x42);

    var src: TestApp = undefined;
    try src.initAt(alloc, testing.io, @splat(0x73), true, true);
    defer src.deinit(alloc);
    const res = createBackup(&src.app, &secret, @splat(0));
    const blob = res.ok;
    defer alloc.free(blob);

    // демон стартовал без сида (режим восстановления), потом профиль
    // создан init-ом поверх: восстановление не затирает его молча
    var dst: TestApp = undefined;
    try dst.initAt(alloc, testing.io, @splat(0x99), false, true);
    defer dst.deinit(alloc);
    var backup = try recovery.open(alloc, blob, &secret);
    defer backup.deinit(alloc);
    try testing.expectError(error.AlreadyProvisioned, applyBackup(&dst.app, &backup));
    try testing.expect(!dst.app.provisioned);
    // сид на диске не тронут (это профиль init-а, не пакета)
    const disk_seed = try paths.loadSeed(dst.app.io, dst.home);
    try testing.expectEqualSlices(u8, &@as([32]u8, @splat(0x99)), &disk_seed);
}
