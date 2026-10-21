//! Загрузка данных демона: миграция каталога, персистентный сид
//! личности (0600), hex-утилиты. Каталоги и сид — единственные файлы
//! ядра вне шифрованного лога (сид — не пользовательские данные).
const std = @import("std");
const stille_messenger = @import("stille-messenger");
const identity = stille_messenger.crypto.identity;
const sysfd = stille_messenger.net.sysfd;
const app_mod = @import("app.zig");
pub const App = app_mod.App;

pub const app_home_max = 512;

/// Каталог данных: ~/.stille-messenger. Старый ~/.shopot мигрирует
/// атомарным rename при первом запуске новой версии.
pub const data_dir_name = ".stille-messenger";

pub const legacy_data_dir_name = ".shopot";

pub fn dataDirPath(out: []u8, home: []const u8, name: []const u8) ![]const u8 {
    return std.fmt.bufPrint(out, "{s}/{s}", .{ home, name });
}

pub fn directoryExists(io: std.Io, path: []const u8) !bool {
    std.Io.Dir.accessAbsolute(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}

/// Подготовить каталог данных. Новый уже есть — ничего не делаем; есть
/// только legacy — переносим атомарно; оба сразу — конфликт, запуск
/// запрещён (две установки молча не сливаются).
pub fn prepareDataDir(io: std.Io, home: []const u8) !void {
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

/// $HOME копия App.home_buf.
pub fn appHomeDir(app: *const App) []const u8 {
    return app.home_buf[0..app.home_len];
}

pub fn stille_messengerDir(io: std.Io, home: []const u8) ![512]u8 {
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

pub fn parseMsgIdHex(text: []const u8) ?[16]u8 {
    if (text.len != 32) return null;
    var id: [16]u8 = undefined;
    _ = std.fmt.hexToBytes(&id, text) catch return null;
    return id;
}
