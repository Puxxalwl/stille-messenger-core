//! Релей: само-хостнутый байтовый сплит для скрытия IP и обхода
//! IP-whitelist. Как MTProto-proxy по роли, но тупее: никакой крипты
//! (E2EE уже внутри stille-messenger-сессии) — релей видит только TLS-подобный шум.
//!
//! Протокол (обе стороны — клиенты релея):
//!   клиент -> релей: [17 03 03 0030][marker 32 + шум 16] (TLS-подобная
//!                    запись AECD-правдоподобной длины: данные + «тег»)
//!   релей -> обоим:  [17 03 03 0012][5A + шум 17]        (спарен)
//!   далее: прозрачный сплит байтов (fake-TLS поток пира-а сквозной).
//! marker = HMAC-SHA256(секрет, "shopot-relay-v1"): вычисляют обе
//! стороны инвайта, релей видит только совпадение значений. Шум —
//! HMAC(marker, метка+наносекунды): выглядит случайно, уникален на
//! запись, без глобального состояния и без CSPRNG-syscall.
//!
//! Пары: первый коннект с marker-ом «владеет» слотом (presence), второй
//! спаривается, лишние коннекты при активной паре закрываются. После
//! обрыва пары слот ОСВОБОЖДАЕТСЯ: любая сторона может перерегистриро-
//! ваться и перекачать соединение без нового инвайта (докачка присутствия).
//! Два вида marker-а: одноразовый инвайт-секрет (invite_secret, фаза
//! знакомства) и ДОЛГОСРОЧНЫЙ контакт-секрет (identity.pairSecret ->
//! presenceMarker, фаза присутствия).
//! Режим демона: `stille-messenger relay <host:port>` — никакого состояния stille-messenger.
const std = @import("std");
const tcp = @import("tcp.zig");
const sysfd = @import("sysfd.zig");

pub const marker_len = 32;
/// Шум-хвост маркер-записи: запись выглядит как «32 байта + тег AECD».
pub const marker_noise_len = 16;
/// Сигнал «спарен» в теле TLS-подобной записи.
pub const pair_signal: u8 = 0x5A;
/// Шум-хвост сигнала: тело записи 1+17 = 18 байт (минимум AECD-записи).
pub const pair_noise_len = 17;
/// Метка домена релея в адресной части инвайта: @r/host:port.
pub const addr_mark = "r/";

// ---- Echo наблюдаемого адреса (NAT-punch, опциональное расширение) ------
// Клиент, собирающийся пробивать прямой путь, спрашивает у релея СВОЙ
// адрес таким, каким его видит релей (reflexive-кандидат). Записи едут
// тем же TLS-подобным каркасом; длина тела echo-записи совпадает с
// pair-сигналом (18), различие — байт типа в теле. Старые клиенты
// ничего не шлют до pair-сигнала (окно peek их не трогает), старые
// релеи не отвечают — клиент просто не получает reflexive.

/// ECHO_REQ: запрос адреса. Тело 1+17 = 18 байт.
pub const echo_req_signal: u8 = 0x5B;
/// ECHO_ACK: ответ релея. Тело: тип 1 + ip 4 (октеты, сетевой порядок)
/// + порт u16 LE + шум 11 = 18 байт.
pub const echo_ack_signal: u8 = 0x5C;
/// Шум-хвост ECHO_ACK (11 байт: тело 1+4+2+11 = 18, AECD-правдоподобно).
pub const echo_ack_noise_len = 11;
/// Полная длина echo-записей на проводе (заголовок + тело 18).
pub const echo_record_len: usize = 5 + 1 + pair_noise_len;

/// Reflexive-адрес, каким релей видит клиента (ip октеты + порт host).
pub const Reflexive = struct {
    ip: [4]u8,
    port: u16,
};

/// Шум для хвостов relay-записей: HMAC-SHA256(marker, метка + наносекунды).
/// Не криптозащита (содержимое и так не секрет), а проводная маскировка:
/// байты неотличимы от случайных и не повторяются между записями.
fn noiseTail(marker: *const [marker_len]u8, out: []u8) void {
    // монотонные наносекунды прямым вызовом (sysfd, паттерн app/main.zig):
    // без глобального состояния, без аллокаций
    const ns = sysfd.monoNs();
    var inbuf: [21 + 8]u8 = undefined;
    @memcpy(inbuf[0..21], "shopot-relay-noise-v1");
    std.mem.writeInt(u64, inbuf[21..29], ns, .little);
    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, &inbuf, marker);
    @memcpy(out, mac[0..out.len]);
}

/// marker из секрета инвайта (обе стороны вычисляют одинаково).
pub fn markerFrom(secret: [16]u8) [marker_len]u8 {
    var m: [marker_len]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&m, "shopot-relay-v1", &secret);
    return m;
}

/// Marker релей-присутствия: из ДОЛГОСРОЧНОГО парного секрета контакта
/// (identity.pairSecret — статик-статик X25519). Отличается доменом от
/// инвайт-marker-а: инвайт одноразовый, этот живёт столько, сколько
/// контакт.
pub fn presenceMarker(pair_secret: [32]u8) [marker_len]u8 {
    var m: [marker_len]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&m, "shopot-relay-presence-v1", &pair_secret);
    return m;
}

/// Клиент: подключиться к релею и зарегистрироваться marker-ом.
/// Возвращает готовый к сплиту коннект (после сигнала 0x5A).
pub fn dial(alloc: std.mem.Allocator, addr: []const u8, secret: [16]u8) !*tcp.TcpConn {
    return dialMarker(alloc, addr, markerFrom(secret));
}

/// То же с echo-запросом (NAT-punch): dial по секрету инвайта +
/// рефлексивный адрес в out (заполняется ТОЛЬКО при ответе relay;
/// старый relay молчит — поле остаётся нетронутым, dial не ломается).
pub fn dialEcho(
    alloc: std.mem.Allocator,
    addr: []const u8,
    secret: [16]u8,
    out_reflexive: ?*Reflexive,
) !*tcp.TcpConn {
    return dialMarkerEcho(alloc, addr, markerFrom(secret), out_reflexive);
}

/// То же с явным marker-ом (присутствие: контакт-секрет).
pub fn dialMarker(alloc: std.mem.Allocator, addr: []const u8, marker: [marker_len]u8) !*tcp.TcpConn {
    const tc = try tcp.dial(alloc, addr);
    errdefer {
        tc.deinit();
        alloc.destroy(tc);
    }
    // [17 03 03 0030][marker 32 + шум 16]: запись len=48 — AECD-подобно
    var w: [5 + marker_len + marker_noise_len]u8 = undefined;
    w[0] = 0x17;
    w[1] = 0x03;
    w[2] = 0x03;
    w[3] = 0;
    w[4] = marker_len + marker_noise_len;
    @memcpy(w[5..][0..marker_len], &marker);
    noiseTail(&marker, w[5 + marker_len ..][0..marker_noise_len]);
    try rawWriteAll(tc.fd, &w);
    // [17 03 03 0012][5A + шум 17]
    var r: [5 + 1 + pair_noise_len]u8 = undefined;
    try rawReadAll(tc.fd, &r);
    if (r[0] != 0x17 or r[1] != 0x03 or r[2] != 0x03 or r[3] != 0 or
        r[4] != 1 + pair_noise_len or r[5] != pair_signal)
        return error.NotRelay;
    return tc;
}

/// Dial с запросом echo (NAT-punch): после маркера шлём ECHO_REQ и читаем
/// записи до pair-сигнала; по пути может прийти ECHO_ACK с нашим
/// наблюдаемым адресом (out_reflexive != null — записать его). Старый
/// релей пришлёт только pair-сигнал — reflexive останется нетронутым.
/// Сокету включается SO_REUSEADDR: punch-движок потом биндит тот же
/// локальный порт (переиспользование NAT-маппинга, см. net/punch.zig).
pub fn dialMarkerEcho(
    alloc: std.mem.Allocator,
    addr: []const u8,
    marker: [marker_len]u8,
    out_reflexive: ?*Reflexive,
) !*tcp.TcpConn {
    const tc = try tcp.dial(alloc, addr);
    errdefer {
        tc.deinit();
        alloc.destroy(tc);
    }
    // SO_REUSEADDR до/spустя connect: флаг сокета учитывается при
    // ПОСЛЕДУЮЩИХ bind-конфликтах punch-сокетов на этот же порт
    sysfd.setReuseAddr(tc.fd);
    // маркер-запись
    var w: [5 + marker_len + marker_noise_len]u8 = undefined;
    w[0] = 0x17;
    w[1] = 0x03;
    w[2] = 0x03;
    w[3] = 0;
    w[4] = marker_len + marker_noise_len;
    @memcpy(w[5..][0..marker_len], &marker);
    noiseTail(&marker, w[5 + marker_len ..][0..marker_noise_len]);
    try rawWriteAll(tc.fd, &w);
    // ECHO_REQ: [17 03 03 0012][5B + шум 17]
    var q: [echo_record_len]u8 = undefined;
    q[0] = 0x17;
    q[1] = 0x03;
    q[2] = 0x03;
    q[3] = 0;
    q[4] = 1 + pair_noise_len;
    q[5] = echo_req_signal;
    noiseTail(&marker, q[6..][0..pair_noise_len]);
    try rawWriteAll(tc.fd, &q);
    // читаем записи: ECHO_ACK (0..n) затем pair-сигнал
    var guard: usize = 0;
    while (true) {
        var r: [echo_record_len]u8 = undefined;
        try rawReadAll(tc.fd, &r);
        if (r[0] != 0x17 or r[1] != 0x03 or r[2] != 0x03 or r[3] != 0 or
            r[4] != 1 + pair_noise_len)
            return error.NotRelay;
        if (r[5] == pair_signal) return tc;
        if (r[5] == echo_ack_signal) {
            if (out_reflexive) |out| {
                out.* = .{
                    .ip = r[6..10].*,
                    .port = std.mem.readInt(u16, r[10..12], .little),
                };
            }
            guard += 1;
            if (guard > 4) return error.NotRelay; // мусорный поток записей
            continue;
        }
        return error.NotRelay;
    }
}

fn rawReadAll(fd: sysfd.fd_t, buf: []u8) !void {
    var got: usize = 0;
    while (got < buf.len) {
        const rc = sysfd.read(fd, buf[got..]) catch return error.Network;
        if (rc == 0) return error.Closed;
        got += rc;
    }
}

fn rawWriteAll(fd: sysfd.fd_t, bytes: []const u8) !void {
    sysfd.writeAll(fd, bytes) catch return error.Network;
}

/// Одна спаренная пара на релее.
const Pending = struct {
    fd: sysfd.fd_t,
    peer_fd: ?sysfd.fd_t = null,
    paired: bool = false,
};

/// Спин-лок (std.Thread.Mutex в этой версии std отсутствует; паттерн app).
const Spin = struct {
    v: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn lock(self: *Spin) void {
        while (self.v.swap(true, .acquire)) std.Thread.yield() catch {};
    }
    fn unlock(self: *Spin) void {
        self.v.store(false, .release);
    }
};

/// Частота проверки второго клиента. 1 мс уменьшает время спаривания
/// (обычно это один RTT), не влияя на пропускную способность уже спаренной пары.
const pairing_poll_ms: u64 = 1;

/// Сервер релея: цикл accept, спаривание, сплит. Блокирует навсегда;
/// stop (для тестов): флаг + закрытый слушатель выводят из цикла.
pub fn serve(alloc: std.mem.Allocator, listener: *tcp.Listener, stop: ?*std.atomic.Value(bool)) void {
    var map = std.AutoHashMap([marker_len]u8, *Pending).init(alloc);
    defer map.deinit();
    var spin = Spin{};

    while (true) {
        const tc = listener.accept(alloc) catch {
            if (stop) |st| {
                if (st.load(.seq_cst)) break;
            }
            continue;
        };
        // Стоп проверяется и после принятого коннекта: shutdown слушающего
        // сокета будит блокированный accept только на linux (на darwin/BSD
        // он возвращает ENOTCONN и accept висит дальше), поэтому переноси-
        // мая остановка — флаг плюс служебный коннект, будящий accept.
        if (stop) |st| {
            if (st.load(.seq_cst)) {
                sysfd.close(tc.fd);
                alloc.destroy(tc);
                break;
            }
        }
        // tc-структура не нужна потоку (он работает с fd): копия в аргументах
        const th = std.Thread.spawn(.{}, relayConn, .{ alloc, &map, &spin, tc.fd }) catch {
            sysfd.close(tc.fd);
            alloc.destroy(tc);
            continue;
        };
        th.detach();
        alloc.destroy(tc);
    }
}

/// Поток одного коннекта релея: прочитать marker, спарить, копировать
/// свой -> пир. Обратное направление копирует пир-поток.
fn relayConn(alloc: std.mem.Allocator, map: *std.AutoHashMap([marker_len]u8, *Pending), spin: *Spin, fd: sysfd.fd_t) void {
    // [17 03 03 0030][marker 32 + шум 16]
    var hdr: [5]u8 = undefined;
    rawReadAll(fd, &hdr) catch return closeFd(fd);
    if (hdr[0] != 0x17 or hdr[1] != 0x03 or hdr[2] != 0x03 or
        hdr[4] != marker_len + marker_noise_len) return closeFd(fd);
    var body: [marker_len + marker_noise_len]u8 = undefined;
    rawReadAll(fd, &body) catch return closeFd(fd);
    const marker: [marker_len]u8 = body[0..marker_len].*;

    // Опциональный ECHO_REQ (NAT-punch): окно 50 мс + MSG_PEEK — старые
    // клиенты до pair-сигнала ничего не шлют (окно их не трогает), а
    // чужие байты не потребляем: peek сверяет точный заголовок записи.
    if (echoRequested(fd)) {
        var req: [echo_record_len]u8 = undefined;
        rawReadAll(fd, &req) catch return closeFd(fd);
        if (req[5] == echo_req_signal) sendEchoAck(fd, &marker);
    }

    const self: *Pending = alloc.create(Pending) catch return closeFd(fd);
    self.* = .{ .fd = fd };

    var peer_fd: sysfd.fd_t = 0;
    var second: bool = false;
    var entry: *Pending = self; // валидно только для second
    {
        spin.lock();
        defer spin.unlock();
        if (map.get(marker)) |other| {
            if (other.paired) {
                // пара активна: слот занят, лишний коннект закрываем
                alloc.destroy(self);
                return closeFd(fd);
            }
            // второй клиент: спарить и оповестить первого; запись
            // ОСТАЁТСЯ в map на время пары (лишние коннекты — см. выше),
            // снятие регистрации и закрытие fd — обязанность second
            other.peer_fd = fd;
            other.paired = true;
            peer_fd = other.fd;
            second = true;
            entry = other;
        } else {
            // первый: зарегистрироваться и ждать пару (поллинг 1 мс)
            map.put(marker, self) catch {
                alloc.destroy(self);
                return closeFd(fd);
            };
            while (!self.paired) {
                spin.unlock();
                sysfd.sleepMs(pairing_poll_ms);
                spin.lock();
                // счёт коннекта мог умереть? пира ждём до закрытия fd
            }
            peer_fd = self.peer_fd.?;
        }
    }
    // сигнал «спарен» обоим: [17 03 03 0012][5A + шум 17]
    if (second) {
        var sig: [5 + 1 + pair_noise_len]u8 = undefined;
        sig[0] = 0x17;
        sig[1] = 0x03;
        sig[2] = 0x03;
        sig[3] = 0;
        sig[4] = 1 + pair_noise_len;
        sig[5] = pair_signal;
        noiseTail(&marker, sig[6..][0..pair_noise_len]);
        rawWriteAll(fd, &sig) catch {};
        rawWriteAll(peer_fd, &sig) catch {};
    }
    // сплит: свой fd -> пир (обратное направление копирует пир-поток)
    splice(fd, peer_fd);
    if (second) {
        // пара закончилась: слот освободить, оба fd закрыть единожды
        // (first закрывать не должен — shutdown ниже будит его splice)
        spin.lock();
        if (map.get(marker)) |cur| {
            if (cur == entry) {
                _ = map.remove(marker);
                alloc.destroy(entry);
            }
        }
        spin.unlock();
        alloc.destroy(self); // свой Pending
        sysfd.shutdownReadWrite(fd);
        sysfd.shutdownReadWrite(peer_fd);
        closeFd(fd);
        closeFd(peer_fd);
    }
    // first: второй поток закрывает оба fd; выходим молча
}

fn closeFd(fd: sysfd.fd_t) void {
    sysfd.close(fd);
}

/// Есть ли за маркером запись ECHO_REQ (окно 50 мс, MSG_PEEK 5 байт
/// заголовка). Чужие/мусорные байты НЕ потребляются.
fn echoRequested(fd: sysfd.fd_t) bool {
    var pfd = [1]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
    const n = std.posix.poll(&pfd, 50) catch return false;
    if (n == 0) return false;
    var hdr: [5]u8 = undefined;
    const got = sysfd.peekIn(fd, &hdr) orelse return false;
    if (got < hdr.len) return false;
    return hdr[0] == 0x17 and hdr[1] == 0x03 and hdr[2] == 0x03 and
        hdr[3] == 0 and hdr[4] == 1 + pair_noise_len;
}

/// Ответить ECHO_ACK: адрес источника, каким его видит релей. Ничего
/// секретного: это адрес TCP-коннекта клиента (релей его и так видит).
fn sendEchoAck(fd: sysfd.fd_t, marker: *const [marker_len]u8) void {
    const sa = sysfd.peerAddrIn(fd) orelse return;
    const ip: [4]u8 = @bitCast(sa.addr);
    const port = std.mem.bigToNative(u16, sa.port);
    var r: [echo_record_len]u8 = undefined;
    r[0] = 0x17;
    r[1] = 0x03;
    r[2] = 0x03;
    r[3] = 0;
    r[4] = 1 + 4 + 2 + echo_ack_noise_len;
    r[5] = echo_ack_signal;
    @memcpy(r[6..10], &ip);
    std.mem.writeInt(u16, r[10..12], port, .little);
    noiseTail(marker, r[12..][0..echo_ack_noise_len]);
    rawWriteAll(fd, &r) catch {};
}

/// Копирование fd -> peer_fd до обрыва. 64 KiB снижает число read/write
/// syscall на bulk transfer; память живёт только на стеке relay-потока.
fn splice(fd: sysfd.fd_t, peer_fd: sysfd.fd_t) void {
    var buf: [64 * 1024]u8 = undefined;
    while (true) {
        const n = sysfd.read(fd, &buf) catch return;
        if (n == 0) return;
        rawWriteAll(peer_fd, buf[0..n]) catch return;
    }
}

// ==== Тесты ====
const testing = std.testing;

test "relay: marker детерминирован и зависит от секрета" {
    const a: [16]u8 = @splat(1);
    const m1 = markerFrom(a);
    const m2 = markerFrom(a);
    const c: [16]u8 = @splat(2);
    const m3 = markerFrom(c);
    try testing.expectEqualSlices(u8, &m1, &m2);
    try testing.expect(!std.mem.eql(u8, &m1, &m3));
    try testing.expect(m1[0] != 0 or m1[1] != 0); // не вырожден
}

test "relay: presenceMarker детерминирован и отделён доменом от инвайта" {
    const sec: [32]u8 = @splat(7);
    const p1 = presenceMarker(sec);
    const p2 = presenceMarker(sec);
    try testing.expectEqualSlices(u8, &p1, &p2);
    const other: [32]u8 = @splat(8);
    try testing.expect(!std.mem.eql(u8, &p1, &presenceMarker(other)));
    // домен отделён от инвайт-marker-а (те же байты секрета)
    const invite16: [16]u8 = @splat(7);
    try testing.expect(!std.mem.eql(u8, &p1, &markerFrom(invite16)));
}

test "relay: шум хвостов записей — не нулевой и уникальный на запись" {
    const m: [marker_len]u8 = @splat(5);
    var a: [marker_noise_len]u8 = undefined;
    var b: [pair_noise_len]u8 = undefined;
    noiseTail(&m, &a);
    // не вырожден
    try testing.expect(a[0] != 0 or a[1] != 0 or a[2] != 0);
    // время идёт — хвосты уникальны (до 64 попыток: наносекунды монотонны)
    var differs = false;
    for (0..64) |_| {
        noiseTail(&m, &b);
        if (!std.mem.eql(u8, &a, b[0..a.len])) {
            differs = true;
            break;
        }
    }
    try testing.expect(differs);
}

/// Релей на свободном loopback-порту + поток serve. Тестовый риг:
/// addr_buf получает «host:port» (len — фактическая длина), th_join —
/// дескриптор потока serve (join обязателен: map живёт в потоке,
/// тесты не должны гонять аллокатор после своего завершения).
fn testRelayStart(alloc: std.mem.Allocator, stop: *std.atomic.Value(bool), addr_buf: *[24]u8, addr_len: *usize, th_join: *?std.Thread) ?*tcp.Listener {
    const l = tcp.listen("127.0.0.1:0") catch return null;
    const lp = alloc.create(tcp.Listener) catch {
        sysfd.close(l.fd);
        return null;
    };
    lp.* = l;
    const port = sysfd.localPort(l.fd) orelse {
        sysfd.close(l.fd);
        alloc.destroy(lp);
        return null;
    };
    const s = std.fmt.bufPrint(addr_buf, "127.0.0.1:{d}", .{port}) catch {
        sysfd.close(l.fd);
        alloc.destroy(lp);
        return null;
    };
    addr_len.* = s.len;
    const th = std.Thread.spawn(.{}, serve, .{ alloc, lp, stop }) catch {
        sysfd.close(l.fd);
        alloc.destroy(lp);
        return null;
    };
    th_join.* = th;
    return lp;
}

/// Остановка: флаг + будящий коннект (close слушателя будит accept
/// только на linux; на darwin нужен служебный коннект) + join потока.
fn testRelayStop(alloc: std.mem.Allocator, lp: *tcp.Listener, stop: *std.atomic.Value(bool), th: ?std.Thread) void {
    stop.store(true, .seq_cst);
    // будим блокированный accept служебным коннектом (портеп рутина serve)
    if (sysfd.socketTcp()) |wk| {
        if (sysfd.localPort(lp.fd)) |port| {
            const sa = sysfd.sockaddrIn(.{ 127, 0, 0, 1 }, port);
            sysfd.connectIn(wk, &sa) catch {};
        }
        sysfd.close(wk);
    } else |_| {}
    lp.deinit();
    alloc.destroy(lp);
    if (th) |t| t.join();
}

/// Дайл клиента в потоке: первый клиент блокируется в dial до появления
/// второго (pair-сигнал приходит только со спариванием) — как в
/// продакшене, где дозвон живут в presence-потоках обеих сторон.
const DialJob = struct {
    alloc: std.mem.Allocator,
    addr: []const u8,
    marker: [marker_len]u8,
    echo: bool,
    result: ?*tcp.TcpConn = null,
    reflexive: Reflexive = undefined,
    err: ?anyerror = null,

    fn run(self: *DialJob) void {
        if (self.echo) {
            self.result = dialMarkerEcho(self.alloc, self.addr, self.marker, &self.reflexive) catch |e| {
                self.err = e;
                return;
            };
        } else {
            self.result = dialMarker(self.alloc, self.addr, self.marker) catch |e| {
                self.err = e;
                return;
            };
        }
    }
};

test "relay: echo наблюдаемого адреса через dialMarkerEcho (loopback)" {
    const alloc = testing.allocator;
    var stop = std.atomic.Value(bool).init(false);
    var addr_buf: [24]u8 = undefined;
    var addr_len: usize = 0;
    var serve_th: ?std.Thread = null;
    const lp = testRelayStart(alloc, &stop, &addr_buf, &addr_len, &serve_th) orelse return error.SkipZigTest;
    const addr = addr_buf[0..addr_len];
    const secret: [16]u8 = @splat(42);
    const marker = markerFrom(secret);
    // два echo-клиента: A в потоке (ждёт пару), B из тест-потока
    var job_a = DialJob{ .alloc = alloc, .addr = addr, .marker = marker, .echo = true };
    const th = try std.Thread.spawn(.{}, DialJob.run, .{&job_a});
    var rb: Reflexive = undefined;
    const cb = try dialMarkerEcho(alloc, addr, marker, &rb);
    th.join();
    const ca = job_a.result orelse return job_a.err.?;
    const ra = job_a.reflexive;
    // loopback: наблюдаемый адрес == реальный адрес сокета
    try testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &ra.ip);
    try testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &rb.ip);
    try testing.expectEqual(sysfd.localPort(ca.fd).?, ra.port);
    try testing.expectEqual(sysfd.localPort(cb.fd).?, rb.port);
    // сплит работает поверх спаренной пары (эхо байтов)
    var probe: [4]u8 = .{ 1, 2, 3, 4 };
    try rawWriteAll(cb.fd, &probe);
    var back: [4]u8 = undefined;
    try rawReadAll(ca.fd, &back);
    try testing.expectEqualSlices(u8, &probe, &back);
    // teardown: shutdown (не close!) обоих клиентов будит relay-потоки
    // по EOF; ОБА fd пары закрывает поток-second — мы только помечаем
    // свои TcpConn закрытыми и ждём очистки до стопа serve
    sysfd.shutdownReadWrite(cb.fd);
    sysfd.shutdownReadWrite(ca.fd);
    sysfd.sleepMs(200);
    cb.closed.store(true, .seq_cst);
    alloc.destroy(cb);
    ca.closed.store(true, .seq_cst);
    alloc.destroy(ca);
    sysfd.sleepMs(50);
    testRelayStop(alloc, lp, &stop, serve_th);
}

test "relay: старый клиент (dialMarker) с echo-релеем — не задет" {
    const alloc = testing.allocator;
    var stop = std.atomic.Value(bool).init(false);
    var addr_buf: [24]u8 = undefined;
    var addr_len: usize = 0;
    var serve_th: ?std.Thread = null;
    const lp = testRelayStart(alloc, &stop, &addr_buf, &addr_len, &serve_th) orelse return error.SkipZigTest;
    const addr = addr_buf[0..addr_len];
    const secret: [16]u8 = @splat(43);
    const marker = markerFrom(secret);
    // старый клиент (без ECHO_REQ) в потоке; новый с echo — из теста
    var job_a = DialJob{ .alloc = alloc, .addr = addr, .marker = marker, .echo = false };
    const th = try std.Thread.spawn(.{}, DialJob.run, .{&job_a});
    var rb: Reflexive = undefined;
    const cb = try dialMarkerEcho(alloc, addr, marker, &rb);
    th.join();
    const ca = job_a.result orelse return job_a.err.?;
    // новый получил reflexive, сплит жив в обе стороны
    try testing.expectEqual(sysfd.localPort(cb.fd).?, rb.port);
    var probe: [3]u8 = .{ 9, 8, 7 };
    try rawWriteAll(ca.fd, &probe);
    var back: [3]u8 = undefined;
    try rawReadAll(cb.fd, &back);
    try testing.expectEqualSlices(u8, &probe, &back);
    // teardown — как в тесте выше: shutdown обоих, fd закроет second
    sysfd.shutdownReadWrite(cb.fd);
    sysfd.shutdownReadWrite(ca.fd);
    sysfd.sleepMs(200);
    cb.closed.store(true, .seq_cst);
    alloc.destroy(cb);
    ca.closed.store(true, .seq_cst);
    alloc.destroy(ca);
    sysfd.sleepMs(50);
    testRelayStop(alloc, lp, &stop, serve_th);
}
