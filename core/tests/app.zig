//! Тесты демона (app-слой): API-хендлеры, инвайты, профиль-код,
//! LAN-поиск, NAT-punch через реальный планировщик и loopback TCP.
//! Корень — шаг test-app (zig build test-app). Тестируемый код приходит
//! модулями: "app-main" (дерево app/, корень main.zig — его pub-алиасы
//! ниже) и "stille-messenger" (библиотека). Тестов в src/ нет — тела
//! живут здесь; в main.zig остаётся только агрегация тестов файлов,
//! недоступных из tests/ относительными импортами.
const std = @import("std");
const builtin = @import("builtin");
const app_main = @import("app-main");
const App = app_main.App;
const stille_messenger = app_main.stille_messenger;
const identity = app_main.identity;
const engine_mod = app_main.engine_mod;
const session_mod = app_main.session_mod;
const envelope = app_main.envelope;
const hb = app_main.hb;
const obf = app_main.obf;
const tcp = app_main.tcp;
const store_mod = app_main.store_mod;
const interfaces = app_main.interfaces;
const invite_mod = app_main.invite_mod;
const endpoints_mod = app_main.endpoints_mod;
const discover_mod = app_main.discover_mod;
const wake = app_main.wake;
const audio_mod = app_main.audio_mod;
const adpcm_mod = app_main.adpcm_mod;
const api_srv = app_main.api_srv;
const api = app_main.api;
const recovery_mod = app_main.recovery_mod;
const recovery_codec = app_main.recovery_codec;
const search_mod = app_main.search_mod;
const config_mod = app_main.config_mod;
const sync_mod = app_main.sync_mod;
const socks5 = app_main.socks5;
const sysfd = app_main.sysfd;
const relay_mod = app_main.relay_mod;
const punch = app_main.punch;
const upnp_mod = app_main.upnp_mod;
const posix = app_main.posix;
const app_mod = app_main.app_mod;
const paths = app_main.paths;
const dispatch = app_main.dispatch;
const presence = app_main.presence;
const lan = app_main.lan;
const dial = app_main.dial;
const receive = app_main.receive;
const events = app_main.events;
const connq = app_main.connq;
const routes = app_main.routes;
const profile_code = app_main.profile_code;
const persist = app_main.persist;
const handlers = app_main.handlers;
const invites = app_main.invites;
const calls = app_main.calls;
const sync_apply = app_main.sync_apply;

test "legacy data dir migrates atomically and conflicts are rejected" {
    const testing = std.testing;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmp.dir.realPathFileAlloc(io, ".", testing.allocator);
    defer testing.allocator.free(home);
    var legacy_buf: [paths.app_home_max * 2]u8 = undefined;
    const legacy = try paths.dataDirPath(&legacy_buf, home, paths.legacy_data_dir_name);
    try std.Io.Dir.createDirAbsolute(io, legacy, @fromBackingInt(@as(u16, 0o700)));
    var legacy_seed_buf: [paths.app_home_max * 2]u8 = undefined;
    const legacy_seed = try std.fmt.bufPrint(&legacy_seed_buf, "{s}/zig-seed", .{legacy});
    const seed_file = try std.Io.Dir.createFileAbsolute(io, legacy_seed, .{ .exclusive = true });
    defer seed_file.close(io);
    const seed_bytes: [32]u8 = @splat(0xA5);
    try seed_file.writePositionalAll(io, &seed_bytes, 0);
    try paths.prepareDataDir(io, home);
    var current_buf: [paths.app_home_max * 2]u8 = undefined;
    const current = try paths.dataDirPath(&current_buf, home, paths.data_dir_name);
    try testing.expect(try paths.directoryExists(io, current));
    try testing.expect(!(try paths.directoryExists(io, legacy)));
    try std.Io.Dir.createDirAbsolute(io, legacy, @fromBackingInt(@as(u16, 0o700)));
    try testing.expectError(error.DataMigrationConflict, paths.prepareDataDir(io, home));
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
            .session_bind = receive.bindSession,
            .session_env_in = receive.envIn,
            .session_on_closed = receive.onClosed,
            .alloc = alloc,
            .io = t.io,
            .id = &id,
            .eng = &eng,
            .log = &log,
            .hb = std.AutoHashMap(i64, hb.State).init(alloc),
            .sess_ctx = std.AutoHashMap(i64, *app_mod.SessCtx).init(alloc),
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
            try t.expectEqual(api.Status.NOT_FOUND, handlers.apiGetMyAvatar(&app, &.{}, &response));
            try t.expectEqual(api.Status.BAD_FRAME, handlers.apiGetMyAvatar(&app, &.{0}, &response));
            try t.expectEqual(@as(usize, 0), response.items().len);
            // A configured id without cached bytes must not return stale data.
            eng.my_avatar_id = @splat(1);
            try t.expectEqual(api.Status.NOT_FOUND, handlers.apiGetMyAvatar(&app, &.{}, &response));
            for ([_][]const u8{ "old avatar", &image }) |bytes| {
                var request = api.Writer.init(alloc);
                defer request.deinit();
                try request.putStr32(bytes);
                var set_response = api.Writer.init(alloc);
                defer set_response.deinit();
                try t.expectEqual(api.Status.OK, handlers.apiSetAvatar(&app, request.items(), &set_response));
                expected_id = set_response.items()[0..16].*;
            }
        } else {
            persist.loadContacts(&app);
        }
        try t.expectEqual(api.Status.OK, handlers.apiGetMyAvatar(&app, &.{}, &response));
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
            const data_dir = try std.fmt.bufPrint(&pb, "{s}/{s}", .{ self.home, paths.data_dir_name });
            std.Io.Dir.createDirAbsolute(io, data_dir, @fromBackingInt(@intCast(0o700))) catch {};
            if (provisioned) {
                var sb: [512]u8 = undefined;
                const sp = try std.fmt.bufPrint(&sb, "{s}/{s}/zig-seed", .{ self.home, paths.data_dir_name });
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
                const lp = try std.fmt.bufPrint(&lb, "{s}/{s}/zig-log", .{ self.home, paths.data_dir_name });
                self.log = try store_mod.Log.open(a, lp, &fix_seed);
            }
            self.app = .{
                .session_bind = receive.bindSession,
                .session_env_in = receive.envIn,
                .session_on_closed = receive.onClosed,
                .alloc = a,
                .io = io,
                .id = &self.id,
                .eng = &self.eng,
                .log = if (self.log) |*l| l else null,
                .hb = std.AutoHashMap(i64, hb.State).init(a),
                .sess_ctx = std.AutoHashMap(i64, *app_mod.SessCtx).init(a),
                .provisioned = provisioned,
                .no_network = true,
            };
            self.app.sync = sync_mod.Sync.init(a, &fix_seed);
            self.app.sync.tr_ctx = &self.app;
            self.app.sync.tr_fn = sync_apply.syncTranslateBundle;
            self.app.home_len = @min(self.home.len, paths.app_home_max);
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
    try t.expectEqual(api.Status.OK, handlers.apiCreateRecoveryBackup(&src.app, request.items(), &response));
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
        try t.expectEqual(api.Status.NOT_INITIALIZED, handlers.apiGetIdentity(&dst.app, &.{}, &g));
        try t.expectEqual(@as(usize, 0), g.items().len);
    }

    // RESTORE: [backup str32][secret 32] → [bundle 64][fp 32][name str16]
    var req2 = api.Writer.init(alloc);
    defer req2.deinit();
    try req2.putStr32(blob);
    try req2.putBytes(&secret);
    var resp2 = api.Writer.init(alloc);
    defer resp2.deinit();
    try t.expectEqual(api.Status.OK, handlers.apiRestoreRecoveryBackup(&dst.app, req2.items(), &resp2));
    try t.expectEqualSlices(u8, &src.id.bundle(), resp2.items()[0..64]);
    var rn = api.Reader.init(resp2.items()[96..]);
    try t.expectEqualStrings("recovery-user", try rn.readStr16());
    try t.expect(!rn.hasMore());
    try t.expect(dst.app.provisioned);

    // повторный RESTORE на живой профиль — ALREADY_PROVISIONED
    try t.expectEqual(api.Status.ALREADY_PROVISIONED, handlers.apiRestoreRecoveryBackup(&dst.app, req2.items(), &resp2));

    // чужой секрет — BAD_RECOVERY, профиль не создаётся
    var dst2: Fixture = undefined;
    try dst2.init(alloc, t.io, @splat(0), false);
    defer dst2.deinit(alloc);
    var req3 = api.Writer.init(alloc);
    defer req3.deinit();
    try req3.putStr32(blob);
    try req3.putBytes(&@as([32]u8, @splat(0xEE)));
    try t.expectEqual(api.Status.BAD_RECOVERY, handlers.apiRestoreRecoveryBackup(&dst2.app, req3.items(), &resp2));
    try t.expect(!dst2.app.provisioned);

    // пустой блоб — BAD_ARGS
    var req4 = api.Writer.init(alloc);
    defer req4.deinit();
    try req4.putStr32("");
    try req4.putBytes(&secret);
    try t.expectEqual(api.Status.BAD_ARGS, handlers.apiRestoreRecoveryBackup(&dst2.app, req4.items(), &resp2));

    // CREATE на непровиженном — NOT_INITIALIZED
    var w5 = api.Writer.init(alloc);
    defer w5.deinit();
    try t.expectEqual(api.Status.NOT_INITIALIZED, handlers.apiCreateRecoveryBackup(&dst2.app, request.items(), &w5));

    // малформ: лишний байт в CREATE — BAD_FRAME
    var req6 = api.Writer.init(alloc);
    defer req6.deinit();
    try req6.putBytes(&secret);
    try req6.putU8(0);
    try t.expectEqual(api.Status.BAD_FRAME, handlers.apiCreateRecoveryBackup(&src.app, req6.items(), &w5));
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
        .session_bind = receive.bindSession,
        .session_env_in = receive.envIn,
        .session_on_closed = receive.onClosed,
        .alloc = alloc,
        .io = t.io,
        .id = &id,
        .eng = &eng,
        .log = null,
        .hb = std.AutoHashMap(i64, hb.State).init(alloc),
        .sess_ctx = std.AutoHashMap(i64, *app_mod.SessCtx).init(alloc),
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
    try t.expectEqual(api.Status.OK, invites.apiAcceptInviteEx(&app, req.items(), &resp));
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
    try t.expectEqual(api.Status.OK, invites.apiAcceptInviteEx(&app, req.items(), &resp2));
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
    try t.expectEqual(api.Status.OK, handlers.apiGetContactState(&app, gc.items(), &gs));
    {
        var rr = api.Reader.init(gs.items());
        try t.expectEqual(@as(u8, @backingInt(api.ConnState.pending)), try rr.readU8());
        try t.expectEqual(@as(u32, 0), try rr.readU32());
        try t.expectEqual(@as(u16, 0), try rr.readU16());
        try t.expectEqual(@as(u32, 0), try rr.readU32());
        try t.expect(!rr.hasMore());
    }
    try t.expectEqual(api.Status.NO_CONTACT, handlers.apiGetContactState(&app, &.{ 9, 0, 0, 0 }, &gs));
    try t.expectEqual(api.Status.BAD_FRAME, handlers.apiGetContactState(&app, &.{1}, &gs));

    // GET_BOOTSTRAP: версия API, epoch, ревизия, счёт, представление
    var bs = api.Writer.init(alloc);
    defer bs.deinit();
    try t.expectEqual(api.Status.OK, handlers.apiGetBootstrap(&app, &.{}, &bs));
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
    try t.expectEqual(api.Status.OK, handlers.apiSubscribeContactUpdates(&app, &conn, &.{}, &ss));
    try t.expect(conn.subscribed);
    {
        var rr = api.Reader.init(ss.items());
        try t.expectEqualSlices(u8, epoch, try rr.readBytes(16));
        try t.expectEqual(rev0, try rr.readU64());
        try t.expect(!rr.hasMore());
    }
    try t.expectEqual(api.Status.BAD_FRAME, handlers.apiSubscribeContactUpdates(&app, &conn, &.{1}, &ss));

    // GET_CONTACTS_DELTA: свежая ревизия — пусто; нулевая — полное кольцо
    var ds = api.Writer.init(alloc);
    defer ds.deinit();
    var dq = api.Writer.init(alloc);
    defer dq.deinit();
    try dq.putBytes(epoch);
    try dq.putU64(rev0);
    try t.expectEqual(api.Status.OK, handlers.apiGetContactsDelta(&app, dq.items(), &ds));
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
    try t.expectEqual(api.Status.OK, handlers.apiGetContactsDelta(&app, dq.items(), &ds));
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
    try t.expectEqual(api.Status.RESYNC_REQUIRED, handlers.apiGetContactsDelta(&app, dq.items(), &ds));
    dq.list.clearRetainingCapacity();
    try dq.putBytes(epoch);
    try dq.putU64(rev0 + 1);
    try t.expectEqual(api.Status.BAD_ARGS, handlers.apiGetContactsDelta(&app, dq.items(), &ds));

    // GET_HISTORY_PAGE: строгий порядок (ts, msg_id), курсор, has_more
    var ids: [5][16]u8 = undefined;
    for (&ids, 0..) |*m, i| {
        m.* = @splat(@truncate(i + 1));
        persist.persistMsg(&app, 1, true, m.*, null, true, 1000 + @as(i64, @intCast(i)), "msg", &.{});
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
    try t.expectEqual(api.Status.OK, handlers.apiGetHistoryPage(&app, pq.items(), &ps));
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
    try t.expectEqual(api.Status.OK, handlers.apiGetHistoryPage(&app, pq.items(), &ps));
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
    try t.expectEqual(api.Status.TOO_BIG, handlers.apiGetHistoryPage(&app, pq.items(), &ps));
    pq.list.clearRetainingCapacity();
    try pq.putU32(99);
    try pq.putU8(0);
    try pq.putU64(0);
    try pq.putBytes(&@as([16]u8, @splat(0)));
    try pq.putU16(5);
    try t.expectEqual(api.Status.NO_CONTACT, handlers.apiGetHistoryPage(&app, pq.items(), &ps));

    // DELETE_CHAT → REMOVED-ревизия в дельте
    var dc = api.Writer.init(alloc);
    defer dc.deinit();
    try dc.putU32(1);
    try t.expectEqual(api.Status.OK, handlers.apiDeleteChat(&app, dc.items(), &ps));
    dq.list.clearRetainingCapacity();
    try dq.putBytes(epoch);
    try dq.putU64(rev0);
    ds.list.clearRetainingCapacity();
    try t.expectEqual(api.Status.OK, handlers.apiGetContactsDelta(&app, dq.items(), &ds));
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
    try t.expectEqual(api.Status.OK, invites.apiCreateInviteEx(&app, cq.items(), &cs));
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
    try t.expectEqual(api.Status.OK, invites.apiGetInviteState(&app, iq.items(), &is));
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
    try t.expectEqual(api.Status.NOT_FOUND, invites.apiGetInviteState(&app, iq2.items(), &is));
    // валидация режимов: прямой без адреса / discovery с адресом / битый mode
    cq.list.clearRetainingCapacity();
    try cq.putU8(@backingInt(api.InviteExMode.direct));
    try cq.putStr16("h");
    try cq.putStr16("");
    try cq.putStr16("");
    try t.expectEqual(api.Status.BAD_ARGS, invites.apiCreateInviteEx(&app, cq.items(), &cs));
    cq.list.clearRetainingCapacity();
    try cq.putU8(9);
    try t.expectEqual(api.Status.BAD_ARGS, invites.apiCreateInviteEx(&app, cq.items(), &cs));
    cq.list.clearRetainingCapacity();
    try cq.putU8(@backingInt(api.InviteExMode.discovery));
    try cq.putStr16("h");
    try cq.putStr16("10.0.0.1:7777");
    try cq.putStr16("");
    try t.expectEqual(api.Status.BAD_ARGS, invites.apiCreateInviteEx(&app, cq.items(), &cs));

    // GET_REACHABLE_ENDPOINTS: не слушаем — пусто (не ошибка)
    var es = api.Writer.init(alloc);
    defer es.deinit();
    try t.expectEqual(api.Status.OK, handlers.apiGetReachableEndpoints(&app, &.{}, &es));
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
        .session_bind = receive.bindSession,
        .session_env_in = receive.envIn,
        .session_on_closed = receive.onClosed,
        .alloc = alloc,
        .io = t.io,
        .id = &id,
        .eng = &eng,
        .log = null,
        .hb = std.AutoHashMap(i64, hb.State).init(alloc),
        .sess_ctx = std.AutoHashMap(i64, *app_mod.SessCtx).init(alloc),
        .provisioned = true,
        .no_network = true,
    };
    defer app.hb.deinit();
    defer app.sess_ctx.deinit();

    // кольцо фиксированного размера: известное число ревизий > cap
    app.contacts_epoch = @splat(7);
    for (0..app_mod.contact_ring_cap + 10) |_| {
        _ = app.eng.addContact("x", @as([64]u8, @splat(0xCD))) catch unreachable;
        // ringAppend без контакта не имеет смысла: используем реальный бамп
        const cid: i64 = @intCast(app.eng.contacts.items.len);
        events.bumpContactLocked(&app, cid);
    }
    const total_rev = app.contacts_rev;
    try t.expectEqual(@as(u64, app_mod.contact_ring_cap + 10), total_rev);
    // самая старая доступная ревизия = rev - cap + 1
    {
        var dq = api.Writer.init(alloc);
        defer dq.deinit();
        try dq.putBytes(&app.contacts_epoch);
        try dq.putU64(total_rev - @as(u64, app_mod.contact_ring_cap));
        var ds = api.Writer.init(alloc);
        defer ds.deinit();
        try t.expectEqual(api.Status.OK, handlers.apiGetContactsDelta(&app, dq.items(), &ds));
        var rr = api.Reader.init(ds.items());
        _ = try rr.readBytes(16);
        try t.expectEqual(total_rev, try rr.readU64());
        try t.expectEqual(@as(u32, app_mod.contact_ring_cap), try rr.readU32());
    }
    // за границей окна — RESYNC_REQUIRED
    var dq = api.Writer.init(alloc);
    defer dq.deinit();
    try dq.putBytes(&app.contacts_epoch);
    try dq.putU64(total_rev - @as(u64, app_mod.contact_ring_cap) - 1);
    var ds = api.Writer.init(alloc);
    defer ds.deinit();
    try t.expectEqual(api.Status.RESYNC_REQUIRED, handlers.apiGetContactsDelta(&app, dq.items(), &ds));
}

// ------------------------------- регрессии событийного подключения (LAN)
/// Стенд: App + один контакт с адресом loopback-листенера. Пир-сторона
/// не поднимается (рукопожатие оборвём закрытием конна) — проверяем, что
/// dial стартует НЕМЕДЛЕННО (kickConnect/handleAnnounce), а не циклами.
const LanTestRig = struct {
    app: App,
    id: identity.Identity,
    eng: engine_mod.Engine,
    lsn: tcp.Listener,
    listen_port: u16,
    peer_bundle: [64]u8,
    alloc: std.mem.Allocator,
};

fn lanRigInit(alloc: std.mem.Allocator, io: std.Io, port: u16) !*LanTestRig {
    const rig = try alloc.create(LanTestRig);
    errdefer alloc.destroy(rig);
    const seed: [32]u8 = @splat(0x5A);
    rig.* = .{
        .app = undefined,
        .id = undefined,
        .eng = undefined,
        .lsn = undefined,
        .listen_port = port,
        .peer_bundle = @splat(0xAA),
        .alloc = alloc,
    };
    rig.id = try identity.Identity.fromSeed(seed);
    errdefer rig.id.deinit();
    rig.eng = engine_mod.Engine.init(alloc, io, rig.id, .{ .ctx = undefined });
    errdefer rig.eng.deinit();
    var pbuf: [24]u8 = undefined;
    const laddr = try std.fmt.bufPrint(&pbuf, "127.0.0.1:{d}", .{port});
    rig.lsn = tcp.listen(laddr) catch {
        rig.eng.deinit();
        rig.id.deinit();
        return error.SkipZigTest; // порт занят окружением
    };
    errdefer rig.lsn.deinit();
    rig.app = .{
        .session_bind = receive.bindSession,
        .session_env_in = receive.envIn,
        .session_on_closed = receive.onClosed,
        .alloc = alloc,
        .io = io,
        .id = &rig.id,
        .eng = &rig.eng,
        .hb = std.AutoHashMap(i64, hb.State).init(alloc),
        .sess_ctx = std.AutoHashMap(i64, *app_mod.SessCtx).init(alloc),
    };
    _ = try rig.eng.addContact("peer", rig.peer_bundle);
    rig.eng.contacts.items[0].setAddr("127.0.0.1", port);
    return rig;
}

/// Доработать connWorker (ждём снятия single-flight слота), собрать конны,
/// освободить стенд. Вызывать в конце теста.
fn lanRigTeardown(rig: *LanTestRig) void {
    var waited: u32 = 0;
    while (connq.connInflight(&rig.app, 1) and waited < 500) : (waited += 1) {
        sysfd.sleepMs(10);
    }
    for (rig.app.raw_conns.items) |tc| {
        tc.deinit();
        rig.alloc.destroy(tc);
    }
    rig.app.raw_conns.deinit(rig.alloc);
    // воркер успевает поднять fake-TLS-обёртку до обрыва установления
    for (rig.app.ftlss.items) |ftls| {
        ftls.deinit();
        rig.alloc.destroy(ftls);
    }
    rig.app.ftlss.deinit(rig.alloc);
    for (rig.app.hist.items) |rec| rig.alloc.free(rec);
    rig.app.hist.deinit(rig.alloc);
    rig.app.hist_idx.deinit(rig.alloc);
    rig.app.conn_work.deinit(rig.alloc);
    rig.app.conn_inflight.deinit(rig.alloc);
    rig.app.conn_st.deinit(rig.alloc);
    rig.app.conn_await.deinit(rig.alloc);
    rig.app.hb.deinit();
    rig.app.sess_ctx.deinit();
    rig.lsn.deinit();
    rig.eng.deinit();
    rig.id.deinit();
    rig.alloc.destroy(rig);
}

/// Читаем ли листенер (пришёл SYN) в течение timeout_ms.
fn lanListenerReadable(lsn: *const tcp.Listener, timeout_ms: i32) !bool {
    var pfd = [1]posix.pollfd{.{ .fd = lsn.fd, .events = posix.POLL.IN, .revents = 0 }};
    const n = try posix.poll(&pfd, timeout_ms);
    return n == 1;
}

test "kick: отправка офлайн-сообщения стартует dial немедленно" {
    const t = std.testing;
    const alloc = t.allocator;
    var rig = try lanRigInit(alloc, t.io, 39771);
    defer lanRigTeardown(rig);
    // SEND_MESSAGE офлайн-контакту: OK + queued-флаг в ответе
    var pw = api.Writer.init(alloc);
    defer pw.deinit();
    try pw.putU32(1);
    try pw.putStr16("привет");
    try pw.putU8(0); // хвост entities: счётчик 0
    var w = api.Writer.init(alloc);
    defer w.deinit();
    try t.expectEqual(api.Status.OK, handlers.apiSendMessage(&rig.app, pw.items(), &w));
    try t.expectEqual(@as(usize, 17), w.items().len);
    try t.expectEqual(@as(u8, 1), w.items()[16]); // queued
    // сообщение в outbox, dial пошёл НЕ от цикла, а от отправки:
    // листенер читаем (SYN дошёл) — до сетевых циклов дело не дошло бы
    // (autodial спит 1с, linker слушает анонсы)
    try t.expect(try lanListenerReadable(&rig.lsn, 2000));
    // пир «принял и закрыл»: закрытие конна тестом гасит установление
    const tc = try rig.lsn.accept(alloc);
    tc.deinit();
    alloc.destroy(tc);
}

test "kick: анонс пира сохраняет адрес и ставит dial в планировщик" {
    const t = std.testing;
    const alloc = t.allocator;
    var rig = try lanRigInit(alloc, t.io, 39772);
    defer lanRigTeardown(rig);
    // наш bundle меньше пира — мы инициатор (детерминизм как в linkerLoop)
    var my_bundle: [64]u8 = @splat(0);
    const ann = discover_mod.Announce{
        .bundle = rig.peer_bundle,
        .port = rig.listen_port,
        .ip = .{ 127, 0, 0, 1 },
        .src_port = 45779,
    };
    lan.handleAnnounce(&rig.app, &my_bundle, ann, null);
    // адрес контакта обновлён из анонса
    var ab: [80]u8 = undefined;
    const got = rig.eng.contacts.items[0].addr(&ab) orelse return error.TestUnexpectedResult;
    var eb: [24]u8 = undefined;
    const want = try std.fmt.bufPrint(&eb, "127.0.0.1:{d}", .{rig.listen_port});
    try t.expectEqualStrings(want, got);
    // dial стартовал через планировщик (не в потоке детекта)
    try t.expect(try lanListenerReadable(&rig.lsn, 2000));
    const tc = try rig.lsn.accept(alloc);
    tc.deinit();
    alloc.destroy(tc);
}

test "short code: генерация и резолв через API" {
    const t = std.testing;
    const alloc = t.allocator;
    var rig = try lanRigInit(alloc, t.io, 39773);
    defer lanRigTeardown(rig);
    var w = api.Writer.init(alloc);
    defer w.deinit();

    // GENERATE_SHORT_CODE для себя (cid 0): детерминированный код
    var pw = api.Writer.init(alloc);
    defer pw.deinit();
    try pw.putU32(0);
    try t.expectEqual(api.Status.OK, invites.apiGenerateShortCode(&rig.app, pw.items(), &w));
    var r = api.Reader.init(w.items());
    const cid0 = try r.readU32();
    const self_code = try r.readStr16();
    try t.expect(!r.hasMore());
    try t.expectEqual(@as(u32, 0), cid0);
    try t.expectEqualSlices(u8, &(invite_mod.shortCodeFromBundle(rig.id.bundle())), self_code);
    // readStr16 — срез в буфер Writer: копируем, буфер переиспользуется
    var self_code_buf: [invite_mod.short_code_len]u8 = undefined;
    @memcpy(&self_code_buf, self_code);

    // GENERATE_SHORT_CODE для контакта (cid 1): код из bundle пира
    w.list.clearRetainingCapacity();
    pw.list.clearRetainingCapacity();
    try pw.putU32(1);
    try t.expectEqual(api.Status.OK, invites.apiGenerateShortCode(&rig.app, pw.items(), &w));
    r = api.Reader.init(w.items());
    const cid1 = try r.readU32();
    const peer_code = try r.readStr16();
    try t.expectEqual(@as(u32, 1), cid1);
    try t.expect(!std.mem.eql(u8, &self_code_buf, peer_code));
    var peer_code_buf: [invite_mod.short_code_len]u8 = undefined;
    @memcpy(&peer_code_buf, peer_code);

    // DECODE_SHORT_CODE кода пира: cid 1 + полный код с bundle/именем/адресом
    w.list.clearRetainingCapacity();
    pw.list.clearRetainingCapacity();
    try pw.putStr16(&peer_code_buf);
    try t.expectEqual(api.Status.OK, invites.apiDecodeShortCode(&rig.app, pw.items(), &w));
    r = api.Reader.init(w.items());
    const d_cid = try r.readU32();
    const full = try r.readStr16();
    try t.expect(!r.hasMore());
    try t.expectEqual(@as(u32, 1), d_cid);
    const inv = try invite_mod.decode(full);
    try t.expectEqualSlices(u8, &rig.peer_bundle, &inv.bundle);
    try t.expectEqualStrings("peer", inv.name());
    try t.expectEqualStrings("127.0.0.1", inv.addr().?);
    try t.expectEqual(rig.listen_port, inv.port);

    // DECODE_SHORT_CODE своего кода: cid 0 + v1-код со своим bundle
    w.list.clearRetainingCapacity();
    pw.list.clearRetainingCapacity();
    try pw.putStr16(&self_code_buf);
    try t.expectEqual(api.Status.OK, invites.apiDecodeShortCode(&rig.app, pw.items(), &w));
    r = api.Reader.init(w.items());
    const s_cid = try r.readU32();
    const s_full = try r.readStr16();
    try t.expectEqual(@as(u32, 0), s_cid);
    const s_inv = try invite_mod.decode(s_full);
    try t.expectEqualSlices(u8, &(rig.id.bundle()), &s_inv.bundle);

    // нормализация: нижний регистр и опечатка I/1 принимаются
    w.list.clearRetainingCapacity();
    pw.list.clearRetainingCapacity();
    var mixed: [invite_mod.short_code_len]u8 = undefined;
    @memcpy(&mixed, &peer_code_buf);
    for (&mixed) |*ch| {
        if (ch.* >= 'A' and ch.* <= 'Z') ch.* += 32;
        if (ch.* == '1') ch.* = 'I';
    }
    try pw.putStr16(&mixed);
    try t.expectEqual(api.Status.OK, invites.apiDecodeShortCode(&rig.app, pw.items(), &w));

    // незнакомец: код корректного формата из чужого bundle -> NOT_FOUND
    w.list.clearRetainingCapacity();
    pw.list.clearRetainingCapacity();
    const stranger = invite_mod.shortCodeFromBundle(@splat(0x77));
    try pw.putStr16(&stranger);
    try t.expectEqual(api.Status.NOT_FOUND, invites.apiDecodeShortCode(&rig.app, pw.items(), &w));

    // сломанный контрольный знак -> BAD_ARGS; кривой payload -> BAD_FRAME
    w.list.clearRetainingCapacity();
    pw.list.clearRetainingCapacity();
    var bad_check: [invite_mod.short_code_len]u8 = undefined;
    @memcpy(&bad_check, &peer_code_buf);
    bad_check[invite_mod.short_code_len - 1] = if (bad_check[invite_mod.short_code_len - 1] == '0') '1' else '0';
    try pw.putStr16(&bad_check);
    try t.expectEqual(api.Status.BAD_ARGS, invites.apiDecodeShortCode(&rig.app, pw.items(), &w));
    try t.expectEqual(api.Status.BAD_FRAME, invites.apiDecodeShortCode(&rig.app, "\x00\x01", &w));
    try t.expectEqual(api.Status.BAD_FRAME, invites.apiGenerateShortCode(&rig.app, "\x01\x02\x03", &w));
    // несуществующий контакт -> NO_CONTACT
    w.list.clearRetainingCapacity();
    pw.list.clearRetainingCapacity();
    try pw.putU32(999);
    try t.expectEqual(api.Status.NO_CONTACT, invites.apiGenerateShortCode(&rig.app, pw.items(), &w));
}

test "profile code: детерминизм, stateless-валидация, реестр не занимается" {
    const t = std.testing;
    const alloc = t.allocator;
    var rig = try lanRigInit(alloc, t.io, 39774);
    defer lanRigTeardown(rig);
    var w = api.Writer.init(alloc);
    defer w.deinit();
    var pw = api.Writer.init(alloc);
    defer pw.deinit();

    // mode 4 (profile) дважды с теми же аргументами: ОДИН И ТОТ ЖЕ код
    // (секрет выведен из сида, а не случайный) и один invite_id
    const mkPayload = struct {
        fn go(p: *api.Writer) !void {
            try p.putU8(@backingInt(api.InviteExMode.profile));
            try p.putStr16("профиль");
            try p.putStr16("");
            try p.putStr16("");
        }
    }.go;
    try mkPayload(&pw);
    try t.expectEqual(api.Status.OK, invites.apiCreateInviteEx(&rig.app, pw.items(), &w));
    var r = api.Reader.init(w.items());
    const code1 = try r.readStr16();
    const id1 = (try r.readBytes(16))[0..16].*;
    try t.expect(!r.hasMore());
    w.list.clearRetainingCapacity();
    pw.list.clearRetainingCapacity();
    try mkPayload(&pw);
    try t.expectEqual(api.Status.OK, invites.apiCreateInviteEx(&rig.app, pw.items(), &w));
    r = api.Reader.init(w.items());
    const code2 = try r.readStr16();
    const id2 = (try r.readBytes(16))[0..16].*;
    try t.expectEqualStrings(code1, code2);
    try t.expectEqualSlices(u8, &id1, &id2);

    // invite_id — детерминированный несекретный маркер личности
    try t.expectEqualSlices(u8, &(profile_code.profileInviteId(&rig.id)), &id1);

    // код — обычный v2: bundle, имя; секрет == статический секрет профиля
    const inv = try invite_mod.decode(code1);
    try t.expect(inv.v2);
    try t.expectEqualSlices(u8, &(rig.id.bundle()), &inv.bundle);
    try t.expectEqualStrings("профиль", inv.name());
    try t.expectEqualSlices(u8, &(profile_code.profileSecret(&rig.id, rig.app.profile_epoch)), &inv.secret);

    // stateless-валидация JOIN: HMAC по транскрипту с секретом из кода
    // совпадает с HMAC по секрету, выведенному из сида; чужой секрет — нет
    var transcript: [32]u8 = undefined;
    for (&transcript, 0..) |*b, i| b.* = @truncate(i *% 7);
    var mac_want: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac_want, &transcript, &(profile_code.profileSecret(&rig.id, rig.app.profile_epoch)));
    var mac_code: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac_code, &transcript, &inv.secret);
    try t.expectEqualSlices(u8, &mac_want, &mac_code);
    var mac_bad: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac_bad, &transcript, &(@as([16]u8, @splat(1))));
    try t.expect(!std.mem.eql(u8, &mac_want, &mac_bad));

    // реестр не занимается: все 4 слота заняты живыми инвайтами —
    // profile всё равно OK (нет TOO_MANY_INVITES), mode 0 — уже нет
    for (0..4) |_| {
        w.list.clearRetainingCapacity();
        pw.list.clearRetainingCapacity();
        try pw.putU8(@backingInt(api.InviteExMode.discovery));
        try pw.putStr16("x");
        try pw.putStr16("");
        try pw.putStr16("");
        try t.expectEqual(api.Status.OK, invites.apiCreateInviteEx(&rig.app, pw.items(), &w));
    }
    w.list.clearRetainingCapacity();
    pw.list.clearRetainingCapacity();
    try pw.putU8(@backingInt(api.InviteExMode.discovery));
    try pw.putStr16("y");
    try pw.putStr16("");
    try pw.putStr16("");
    try t.expectEqual(api.Status.TOO_MANY_INVITES, invites.apiCreateInviteEx(&rig.app, pw.items(), &w));
    w.list.clearRetainingCapacity();
    pw.list.clearRetainingCapacity();
    try mkPayload(&pw);
    try t.expectEqual(api.Status.OK, invites.apiCreateInviteEx(&rig.app, pw.items(), &w));

    // GET_INVITE_STATE по маркеру профиля: active, бессрочно
    w.list.clearRetainingCapacity();
    pw.list.clearRetainingCapacity();
    try pw.putBytes(&id1);
    try t.expectEqual(api.Status.OK, invites.apiGetInviteState(&rig.app, pw.items(), &w));
    r = api.Reader.init(w.items());
    try t.expectEqual(@as(u8, 0), try r.readU8()); // active
    try t.expectEqual(@as(u32, 0), try r.readU32());
    try t.expectEqual(@as(i64, 0), try r.readI64());
}

test "profile code: REGENERATE — слитый код умирает, данные живут" {
    const t = std.testing;
    const alloc = t.allocator;
    var rig = try lanRigInit(alloc, t.io, 39775);
    defer lanRigTeardown(rig);
    var w = api.Writer.init(alloc);
    defer w.deinit();
    var pw = api.Writer.init(alloc);
    defer pw.deinit();

    // код эпохи 0: секрет = эпоха 0 в HKDF
    try pw.putU8(@backingInt(api.InviteExMode.profile));
    try pw.putStr16("профиль");
    try pw.putStr16("");
    try pw.putStr16("");
    try t.expectEqual(api.Status.OK, invites.apiCreateInviteEx(&rig.app, pw.items(), &w));
    var r = api.Reader.init(w.items());
    const code0 = try r.readStr16();
    const inv0 = try invite_mod.decode(code0);
    try t.expectEqualSlices(u8, &(profile_code.profileSecret(&rig.id, 0)), &inv0.secret);

    // REGENERATE: эпоха 1; persisted=0 (в rig нет лога — режим «продолжаю
    // без хранения», честно отражён в ответе)
    w.list.clearRetainingCapacity();
    try t.expectEqual(api.Status.OK, invites.apiRegenerateProfileCode(&rig.app, &.{}, &w));
    r = api.Reader.init(w.items());
    try t.expectEqual(@as(u32, 1), try r.readU32());
    try t.expectEqual(@as(u8, 0), try r.readU8());
    try t.expect(!r.hasMore());
    try t.expectEqual(@as(u32, 1), rig.app.profile_epoch);

    // новый код = ДРУГОЙ секрет (эпоха в HKDF), bundle тот же
    w.list.clearRetainingCapacity();
    pw.list.clearRetainingCapacity();
    try pw.putU8(@backingInt(api.InviteExMode.profile));
    try pw.putStr16("профиль");
    try pw.putStr16("");
    try pw.putStr16("");
    try t.expectEqual(api.Status.OK, invites.apiCreateInviteEx(&rig.app, pw.items(), &w));
    r = api.Reader.init(w.items());
    const code1 = try r.readStr16();
    const inv1 = try invite_mod.decode(code1);
    try t.expectEqualSlices(u8, &(profile_code.profileSecret(&rig.id, 1)), &inv1.secret);
    try t.expectEqualSlices(u8, &(rig.id.bundle()), &inv1.bundle);
    try t.expect(!std.mem.eql(u8, &(profile_code.profileSecret(&rig.id, 0)), &inv1.secret));

    // слитый код эпохи 0 больше НЕ проходит JOIN-проверку: HMAC по его
    // секрету не совпадает с HMAC текущей эпохи
    var transcript: [32]u8 = undefined;
    for (&transcript, 0..) |*b, i| b.* = @truncate(i *% 13);
    var mac_cur: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac_cur, &transcript, &(profile_code.profileSecret(&rig.id, rig.app.profile_epoch)));
    var mac_leaked: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac_leaked, &transcript, &(profile_code.profileSecret(&rig.id, 0)));
    try t.expect(!std.mem.eql(u8, &mac_cur, &mac_leaked));

    // кривой payload → BAD_FRAME
    const bad_payload = [_]u8{1};
    try t.expectEqual(api.Status.BAD_FRAME, invites.apiRegenerateProfileCode(&rig.app, &bad_payload, &w));
}

// ------------------------------------------------------- NAT-punch (2.9.0)

/// Мини-приложение без сети (no_network): карта punch-маршрутов,
/// правило инициатора, приём PUNCH_CANDIDATES. Транспортный уровень
/// (dialMarkerEcho, simultaneous open, вторая сессия поверх пробитого
/// конна) покрыт интеграционным тестом tests/integration.zig.
const PunchRig = struct {
    app: App,
    id: identity.Identity,
    eng: engine_mod.Engine,

    fn init(alloc: std.mem.Allocator, io: std.Io) !*PunchRig {
        const rig = try alloc.create(PunchRig);
        errdefer alloc.destroy(rig);
        const seed: [32]u8 = @splat(0x6B);
        rig.* = .{ .app = undefined, .id = undefined, .eng = undefined };
        rig.id = try identity.Identity.fromSeed(seed);
        errdefer rig.id.deinit();
        rig.eng = engine_mod.Engine.init(alloc, io, rig.id, .{ .ctx = undefined });
        errdefer rig.eng.deinit();
        rig.app = .{
            .session_bind = receive.bindSession,
            .session_env_in = receive.envIn,
            .session_on_closed = receive.onClosed,
            .alloc = alloc,
            .io = io,
            .id = &rig.id,
            .eng = &rig.eng,
            .hb = std.AutoHashMap(i64, hb.State).init(alloc),
            .sess_ctx = std.AutoHashMap(i64, *app_mod.SessCtx).init(alloc),
            .no_network = true,
        };
        return rig;
    }

    fn deinit(self: *PunchRig, alloc: std.mem.Allocator) void {
        self.app.hb.deinit();
        self.app.sess_ctx.deinit();
        self.app.punch_routes.deinit(alloc);
        self.app.punch_runs.deinit(alloc);
        self.eng.deinit();
        self.id.deinit();
        alloc.destroy(self);
    }
};

test "NAT-punch: PUNCH_CANDIDATES пира пишутся в маршрут, воркер не стартует (no_network)" {
    const t = std.testing;
    const alloc = t.allocator;
    const rig = try PunchRig.init(alloc, t.io);
    defer rig.deinit(alloc);
    const app = &rig.app;
    var id_b = try identity.Identity.fromSeed(@splat(0x6C));
    defer id_b.deinit();
    _ = try rig.eng.addContact("b", id_b.bundle());
    // маршрут relay-сессии (как его пишет sendPunchCandidatesLocked)
    try app.punch_routes.put(alloc, 1, .{
        .local_ip = .{ 127, 0, 0, 1 },
        .local_port = 40001,
        .reflexive = .{ .ip = .{ 203, 0, 113, 7 }, .port = 40123 },
        .peer = .{ .count = 0, .types = @splat(0), .ips = @splat(@splat(0)), .ports = @splat(0) },
    });
    // кадр пира: reflexive + host
    var p: envelope.Punch = .{
        .count = 2,
        .types = .{ envelope.punch_reflexive, envelope.punch_host, 0, 0, 0, 0, 0, 0 },
        .ips = .{ .{ 198, 51, 100, 9 }, .{ 192, 168, 1, 42 }, .{ 0, 0, 0, 0 }, .{ 0, 0, 0, 0 }, .{ 0, 0, 0, 0 }, .{ 0, 0, 0, 0 }, .{ 0, 0, 0, 0 }, .{ 0, 0, 0, 0 } },
        .ports = .{ 51234, 7777, 0, 0, 0, 0, 0, 0 },
    };
    routes.handlePunchInLocked(app, 1, p);
    const route = app.punch_routes.get(1) orelse return error.NoRoute;
    try t.expectEqual(@as(u8, 2), route.peer.count);
    try t.expectEqual(envelope.punch_reflexive, route.peer.types[0]);
    try t.expectEqualSlices(u8, &p.ips[0], &route.peer.ips[0]);
    try t.expectEqual(@as(u16, 51234), route.peer.ports[0]);
    // наши поля маршрута не тронуты кадром пира
    try t.expectEqual(@as(u16, 40001), route.local_port);
    try t.expectEqual(@as(u16, 40123), route.reflexive.port);
    // no_network: воркер не стартует (запуск — только сетевому демону)
    try t.expect(!app.punch_runs.contains(1));
    // без маршрута (прямой путь) кадр игнорируется молча
    routes.handlePunchInLocked(app, 2, p);
    try t.expect(!app.punch_routes.contains(2));
}

test "NAT-punch: правило инициатора — меньший bundle, устройство-линк — держатель" {
    const t = std.testing;
    const alloc = t.allocator;
    const rig = try PunchRig.init(alloc, t.io);
    defer rig.deinit(alloc);
    const app = &rig.app;
    // bundle меньше нашего — мы инициатор; больше — респондер
    const smaller: [64]u8 = @splat(0x01);
    const bigger: [64]u8 = @splat(0xFE);
    _ = try rig.eng.addContact("small", smaller);
    _ = try rig.eng.addContact("big", bigger);
    try t.expect(!routes.punchAmInitiatorLocked(app, 1)); // bundle пира меньше нашего
    try t.expect(routes.punchAmInitiatorLocked(app, 2)); // bundle пира больше нашего
    // устройство-линк (bundle равны нашему): инициатор — держатель кода
    const my_bundle = rig.id.bundle();
    _ = try rig.eng.addContact("twin", my_bundle);
    rig.eng.contacts.items[2].dev_role = app_mod.dev_role_holder;
    try t.expect(routes.punchAmInitiatorLocked(app, 3));
    rig.eng.contacts.items[2].dev_role = 1; // не держатель — ждём
    try t.expect(!routes.punchAmInitiatorLocked(app, 3));
    // контакт не существует: false, не падаем
    try t.expect(!routes.punchAmInitiatorLocked(app, 99));
}

// ---- direct-first (2.10.0): белые тесты ----------------------------------

test "direct-first: persist.splitHostPort понимает [v6]:port" {
    const t = std.testing;
    var hp = persist.splitHostPort("[2001:db8::1]:7777");
    try t.expectEqualStrings("2001:db8::1", hp.host);
    try t.expectEqual(@as(u16, 7777), hp.port);
    hp = persist.splitHostPort("192.168.1.5:7777");
    try t.expectEqualStrings("192.168.1.5", hp.host);
    try t.expectEqual(@as(u16, 7777), hp.port);
    hp = persist.splitHostPort("[::1]:0");
    try t.expectEqual(@as(u16, 0), hp.port);
    hp = persist.splitHostPort("no-port");
    try t.expectEqual(@as(u16, 0), hp.port);
}

test "direct-first: Contact.addr рендерит v6 в скобках" {
    const t = std.testing;
    var c: engine_mod.Contact = .{};
    c.setAddr("2001:db8:1:2:3:4:5:6", 7777);
    var buf: [80]u8 = undefined;
    const a = c.addr(&buf).?;
    try t.expectEqualStrings("[2001:db8:1:2:3:4:5:6]:7777", a);
    // v4 — без скобок, как раньше
    c.setAddr("192.168.1.5", 7777);
    const a4 = c.addr(&buf).?;
    try t.expectEqualStrings("192.168.1.5:7777", a4);
}
