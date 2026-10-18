//! Перечисление локальных IPv4-адресов активных интерфейсов (0.3.0 /
//! API 2.7.0, GET_REACHABLE_ENDPOINTS): кандидаты для QR-приглашения с
//! прямым LAN-адресом. Порт НЕ входит — его добавляет вызывающий
//! (listen-порт демона): здесь только хосты.
//!
//! Linux — netlink RTM_GETADDR-дамп прямыми syscall-ами std.os.linux
//! (паттерн net/sysfd.zig); Darwin — libc getifaddrs (extern-объявления —
//! часть std-модели, зависимостей не добавляют). Парсер дампа — чистая
//! функция для детерминированных тестов.
//!
//! Адреса-кандидаты отфильтрованы: unspecified/loopback/multicast/
//! broadcast НЕ попадают в выдачу. Доступность адреса с ДРУГОГО устройства
//! не проверяется (нет probe-трафика): это список локальных кандидатов.
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

/// Максимум адресов в выдаче.
pub const max_endpoints = 16;
/// Длина строкового IPv4-хоста ("255.255.255.255").
pub const host_max = 16;
/// NETLINK_ROUTE (linux/netlink.h, в std нет константы).
const netlink_route: c_int = 16;
/// NLMSG_HDRLEN = 16 (sizeof nlmsghdr, выравнивание учтено).
const nlmsg_hdr_len: usize = @sizeOf(std.os.linux.nlmsghdr);
/// ifaddrmsg (linux/if_addr.h, в std нет структуры).
const ifaddrmsg = extern struct {
    family: u8,
    prefixlen: u8,
    flags: u8,
    scope: u8,
    index: u32,
};
/// Выравнивание netlink-сообщений/атрибутов (4 байта).
fn nlAlign(n: u32) u32 {
    return (n + 3) & ~@as(u32, 3);
}

// ---- Darwin: libc-externs (getifaddrs) ------------------------------------
const darwin_cabi = struct {
    const ifaddrs = extern struct {
        next: ?*ifaddrs,
        name: ?[*:0]u8,
        flags: c_uint,
        addr: ?*posix.sockaddr,
        netmask: ?*posix.sockaddr,
        dstaddr: ?*posix.sockaddr,
        data: ?*anyopaque,
    };
    extern "c" fn getifaddrs(ifap: *?*ifaddrs) c_int;
};

/// Отфильтрованный кандидат: НЕ unspecified, loopback, multicast, broadcast.
pub fn isCandidateV4(ip: [4]u8) bool {
    if (std.mem.eql(u8, &ip, &@as([4]u8, @splat(0)))) return false; // 0.0.0.0
    if (ip[0] == 127) return false; // loopback /8
    if (ip[0] >= 224 and ip[0] <= 239) return false; // multicast /4
    if (std.mem.eql(u8, &ip, &@as([4]u8, @splat(255)))) return false; // 255.255.255.255
    return true;
}

/// "a.b.c.d" (хост, без порта) в буфер.
pub fn fmtHost(buf: []u8, ip: [4]u8) []const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch "?";
}

/// Парсер netlink-дампа RTM_GETADDR (Linux): поток nlmsghdr-сообщений,
/// RTM_NEWADDR → ifaddrmsg → rtattr IFA_LOCAL (fallback IFA_ADDRESS для
/// p2p), family AF_INET. Битые/усечённые записи пропускаются молча
/// (dump — не доверенный ввод, но отказывать выдаче из-за мусора нельзя).
/// Один IFA-атрибут сообщения даёт ОДИН адрес (LOCAL приоритетнее).
/// Возвращает число добавленных адресов (≤ max_endpoints).
pub fn parseNetlinkAddrDump(bytes: []const u8, out_ip: *[max_endpoints][4]u8) usize {
    var count: usize = 0;
    var off: usize = 0;
    while (off + nlmsg_hdr_len <= bytes.len) {
        const hdr: *const std.os.linux.nlmsghdr = @ptrCast(@alignCast(bytes[off..][0..nlmsg_hdr_len]));
        const len = hdr.len;
        if (len < nlmsg_hdr_len) return count; // мусор: выравнивание потеряно
        const msg_end = off + len;
        if (msg_end > bytes.len) return count; // усечённый dump
        if (hdr.type == .RTM_NEWADDR and len >= nlmsg_hdr_len + @sizeOf(ifaddrmsg)) {
            const ifa: *const ifaddrmsg = @ptrCast(@alignCast(bytes[off + nlmsg_hdr_len ..][0..@sizeOf(ifaddrmsg)]));
            if (ifa.family == posix.AF.INET) {
                // цепочка rtattr после ifaddrmsg
                var aoff = off + nlmsg_hdr_len + @sizeOf(ifaddrmsg);
                var local: ?[4]u8 = null;
                var address: ?[4]u8 = null;
                while (aoff + 4 <= msg_end) {
                    const attr_len = std.mem.readInt(u16, bytes[aoff..][0..2], .little);
                    const attr_type = std.mem.readInt(u16, bytes[aoff + 2 ..][0..2], .little);
                    if (attr_len < 4 or aoff + attr_len > msg_end) break;
                    const data = bytes[aoff + 4 .. @min(aoff + attr_len, msg_end)];
                    if (data.len >= 4) {
                        const ip: [4]u8 = data[0..4].*;
                        switch (attr_type) {
                            2 => local = ip, // IFA_LOCAL
                            1 => address = ip, // IFA_ADDRESS
                            else => {},
                        }
                    }
                    aoff += nlAlign(attr_len);
                }
                const chosen = local orelse address orelse null;
                if (chosen) |ip| {
                    if (count < max_endpoints) {
                        out_ip[count] = ip;
                        count += 1;
                    }
                }
            }
        }
        if (len == 0) return count;
        off += nlAlign(len);
        if (hdr.type == .DONE) return count;
    }
    return count;
}

/// Локальные IPv4-хосты активных интерфейсов (кандидаты, без порта),
/// дедуп по адресам. error.Network — перечисление недоступно (нет сети,
/// ОС отказала): вызывающий показывает «прямой адрес недоступен».
pub fn enumerateLocalV4(out_ip: *[max_endpoints][4]u8) error{Network}!usize {
    if (builtin.os.tag == .linux) {
        return enumerateLinux(out_ip);
    }
    return enumerateDarwin(out_ip);
}

/// Linux: netlink RTM_GETADDR-дамп. Стековые буферы (без аллокаций):
/// дамп больше буфера читается кусками — сообщения multipart, парсер
/// вызывается на каждом куске, done-маркер завершает.
fn enumerateLinux(out_ip: *[max_endpoints][4]u8) error{Network}!usize {
    const fd = std.os.linux.socket(
        posix.AF.NETLINK,
        posix.SOCK.RAW | posix.SOCK.CLOEXEC,
        @intCast(netlink_route),
    );
    const sock_err = std.os.linux.errno(fd);
    if (sock_err != .SUCCESS) return error.Network;
    errdefer sysfdClose(@intCast(fd));
    var sa = std.os.linux.sockaddr.nl{ .pid = 0, .groups = 0 };
    const bind_rc = std.os.linux.bind(@intCast(fd), @ptrCast(&sa), @sizeOf(std.os.linux.sockaddr.nl));
    if (std.os.linux.errno(bind_rc) != .SUCCESS) return error.Network;
    // запрос: nlmsghdr + ifaddrmsg (24 байта)
    var req: [nlmsg_hdr_len + @sizeOf(ifaddrmsg)]u8 = @splat(0);
    {
        const hdr: *std.os.linux.nlmsghdr = @ptrCast(@alignCast(&req));
        hdr.len = @intCast(req.len);
        hdr.type = .RTM_GETADDR;
        hdr.flags = std.os.linux.NLM_F_REQUEST | std.os.linux.NLM_F_DUMP;
        hdr.seq = 1;
        hdr.pid = 0;
        const ifa: *ifaddrmsg = @ptrCast(@alignCast(req[nlmsg_hdr_len..]));
        ifa.family = posix.AF.INET;
    }
    const send_rc = std.os.linux.sendto(@intCast(fd), &req, req.len, 0, null, 0);
    if (std.os.linux.errno(send_rc) != .SUCCESS) return error.Network;
    var count: usize = 0;
    var buf: [16384]u8 = undefined;
    while (true) {
        const rc = std.os.linux.recvfrom(@intCast(fd), &buf, buf.len, 0, null, null);
        const e = std.os.linux.errno(rc);
        if (e != .SUCCESS) return error.Network;
        const got: usize = @intCast(rc);
        if (got == 0) return error.Network;
        // первый заголовок куска: done/error завершают дамп
        if (got >= nlmsg_hdr_len) {
            const hdr: *const std.os.linux.nlmsghdr = @ptrCast(@alignCast(buf[0..nlmsg_hdr_len]));
            if (hdr.type == .DONE) break;
            if (hdr.type == .ERROR) return error.Network;
        }
        var tmp: [max_endpoints][4]u8 = undefined;
        const added = parseNetlinkAddrDump(buf[0..got], &tmp);
        for (tmp[0..added]) |ip| {
            var dup = false;
            for (out_ip[0..count]) |o| {
                if (std.mem.eql(u8, &o, &ip)) {
                    dup = true;
                    break;
                }
            }
            if (!dup and isCandidateV4(ip)) {
                if (count >= max_endpoints) break;
                out_ip[count] = ip;
                count += 1;
            }
        }
        if (count >= max_endpoints) break;
    }
    return count;
}

/// Закрытие fd (Linux-ветка): единая точка для errdefer.
fn sysfdClose(fd: posix.socket_t) void {
    _ = std.os.linux.close(@intCast(fd));
}

/// Darwin: getifaddrs по списку интерфейсов.
fn enumerateDarwin(out_ip: *[max_endpoints][4]u8) error{Network}!usize {
    var ifap: ?*darwin_cabi.ifaddrs = null;
    if (darwin_cabi.getifaddrs(&ifap) != 0) return error.Network;
    var count: usize = 0;
    var it = ifap;
    while (it) |ifa| : (it = ifa.next) {
        const sa = ifa.addr orelse continue;
        if (sa.family != posix.AF.INET) continue;
        const in: *const posix.sockaddr.in = @ptrCast(@alignCast(sa));
        const ip: [4]u8 = @bitCast(in.addr);
        if (!isCandidateV4(ip)) continue;
        var dup = false;
        for (out_ip[0..count]) |o| {
            if (std.mem.eql(u8, &o, &ip)) {
                dup = true;
                break;
            }
        }
        if (dup) continue;
        if (count >= max_endpoints) break;
        out_ip[count] = ip;
        count += 1;
    }
    if (ifap) |head| darwinFreeIfAddrs(head);
    return count;
}

/// freeifaddrs — имя libc-функции, extern объявлен с дисambig-обёрткой.
extern "c" fn freeifaddrs(ifap: ?*anyopaque) void;
fn darwinFreeIfAddrs(head: *darwin_cabi.ifaddrs) void {
    freeifaddrs(@ptrCast(head));
}

// ------------------------------------------------------------------ тесты

test "endpoints: фильтр кандидатов" {
    const t = std.testing;
    try t.expect(!isCandidateV4(.{ 0, 0, 0, 0 }));
    try t.expect(!isCandidateV4(.{ 127, 0, 0, 1 }));
    try t.expect(!isCandidateV4(.{ 127, 5, 5, 5 }));
    try t.expect(!isCandidateV4(.{ 224, 0, 0, 5 }));
    try t.expect(!isCandidateV4(.{ 239, 1, 2, 3 }));
    try t.expect(!isCandidateV4(.{ 255, 255, 255, 255 }));
    try t.expect(isCandidateV4(.{ 192, 168, 1, 5 }));
    try t.expect(isCandidateV4(.{ 10, 0, 0, 7 }));
    try t.expect(isCandidateV4(.{ 169, 254, 3, 4 }));
}

test "endpoints: fmtHost" {
    var buf: [host_max]u8 = undefined;
    try std.testing.expectEqualStrings("192.168.100.100", fmtHost(&buf, .{ 192, 168, 100, 100 }));
}

/// Сборка синтетического netlink-сообщения RTM_NEWADDR в буфер.
const TestAttr = struct { kind: u16, ip: [4]u8 };
fn putAddrMsg(out: *std.ArrayListUnmanaged(u8), alloc: std.mem.Allocator, family: u8, attrs: []const TestAttr) !void {
    var msg_len: u32 = @intCast(nlmsg_hdr_len + @sizeOf(ifaddrmsg));
    for (attrs) |_| msg_len += 8;
    const hdr: std.os.linux.nlmsghdr = .{
        .len = msg_len,
        .type = .RTM_NEWADDR,
        .flags = std.os.linux.NLM_F_MULTI,
        .seq = 1,
        .pid = 0,
    };
    try out.appendSlice(alloc, std.mem.asBytes(&hdr));
    const ifa = ifaddrmsg{ .family = family, .prefixlen = 24, .flags = 0, .scope = 0, .index = 2 };
    try out.appendSlice(alloc, std.mem.asBytes(&ifa));
    for (attrs) |a| {
        const attr_len: u16 = 8;
        try out.appendSlice(alloc, std.mem.asBytes(&attr_len));
        try out.appendSlice(alloc, std.mem.asBytes(&a.kind));
        try out.appendSlice(alloc, &a.ip);
    }
}

test "endpoints: parseNetlinkAddrDump — extraction и мусор" {
    const t = std.testing;
    const alloc = t.allocator;
    var dump = std.ArrayListUnmanaged(u8).empty;
    defer dump.deinit(alloc);
    // сообщение 1: AF_INET + IFA_LOCAL 192.168.1.5
    try putAddrMsg(&dump, alloc, posix.AF.INET, &.{.{ .kind = 2, .ip = .{ 192, 168, 1, 5 } }});
    // сообщение 2: AF_INET + только IFA_ADDRESS (p2p) 10.0.0.7
    try putAddrMsg(&dump, alloc, posix.AF.INET, &.{.{ .kind = 1, .ip = .{ 10, 0, 0, 7 } }});
    // сообщение 3: AF_INET6 — пропустить
    try putAddrMsg(&dump, alloc, 10, &.{.{ .kind = 2, .ip = .{ 1, 2, 3, 4 } }});
    // сообщение 4: IFA_LOCAL + IFA_ADDRESS — берётся ОДИН (LOCAL)
    try putAddrMsg(&dump, alloc, posix.AF.INET, &.{
        .{ .kind = 2, .ip = .{ 172, 16, 0, 1 } },
        .{ .kind = 1, .ip = .{ 172, 16, 0, 2 } },
    });
    // done-маркер
    const hdr_done: std.os.linux.nlmsghdr = .{ .len = @intCast(nlmsg_hdr_len), .type = .DONE, .flags = 0, .seq = 2, .pid = 0 };
    try dump.appendSlice(alloc, std.mem.asBytes(&hdr_done));

    var out: [max_endpoints][4]u8 = undefined;
    const n = parseNetlinkAddrDump(dump.items, &out);
    try t.expectEqual(@as(usize, 3), n);
    try t.expectEqualSlices(u8, &@as([4]u8, .{ 192, 168, 1, 5 }), &out[0]);
    try t.expectEqualSlices(u8, &@as([4]u8, .{ 10, 0, 0, 7 }), &out[1]);
    try t.expectEqualSlices(u8, &@as([4]u8, .{ 172, 16, 0, 1 }), &out[2]);
    // усечённый dump (обрыв посреди сообщения) — без паники
    const n2 = parseNetlinkAddrDump(dump.items[0 .. dump.items.len - 3], &out);
    try t.expect(n2 <= 3);
    // пустой dump
    try t.expectEqual(@as(usize, 0), parseNetlinkAddrDump(&.{}, &out));
}
