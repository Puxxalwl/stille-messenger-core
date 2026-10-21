//! Звонки: state machine вызова, звуковые циклы (mic 20 мс, jitter
//! buffer), ADPCM/PCM кодирование, AEAD-кадры аудио.
const std = @import("std");
const stille_messenger = @import("stille-messenger");
const envelope = stille_messenger.proto.envelope;
const audio_mod = @import("audio.zig");
const adpcm_mod = @import("adpcm.zig");
const api = @import("api.zig");
const app_mod = @import("app.zig");
const engine_mod = stille_messenger.core.engine;
const sysfd = stille_messenger.net.sysfd;
const api_srv = @import("api_server.zig");
pub const App = app_mod.App;
const events = @import("events.zig");

// ------------------------------------------------------------- звонки
/// Входящий сигнал: offer — гудки, accept — линия вверх, reject/hangup — конец.
pub fn onCallSignalEv(ctx: *anyopaque, from: *const engine_mod.Contact, op: u8, call_id: [16]u8) void {
    // ВЫЗЫВАЕТСЯ ПОД app.mu (из envIn) — второго захвата быть не должно.
    const app: *App = @ptrCast(@alignCast(ctx));
    switch (op) {
        audio_mod.CallOp.offer => {
            if (app.call) |c| {
                // уже в звонке: отклоняем
                _ = app.eng.callSignal(c.cid, audio_mod.CallOp.reject, call_id) catch {};
                return;
            }
            const cid = app_mod.contactIdByBundle(app, from.bundle) orelse return;
            const c = app.alloc.create(app_mod.CallState) catch return;
            const zero_secret: [32]u8 = @splat(0);
            const secret = if (app.eng.sessions.get(cid)) |sess| sess.callSecret(call_id) else zero_secret;
            c.* = .{ .cid = cid, .call_id = call_id, .secret = secret };
            app.call = c;
            events.evCallState(app, cid, call_id, .offer);
        },
        audio_mod.CallOp.accept => {
            const c = app.call orelse return;
            if (!std.mem.eql(u8, &c.call_id, &call_id)) return;
            startCallAudio(app, c);
            events.evCallState(app, c.cid, call_id, .accept);
        },
        audio_mod.CallOp.reject => {
            const c = app.call orelse return;
            if (!std.mem.eql(u8, &c.call_id, &call_id)) return;
            events.evCallState(app, c.cid, call_id, .reject);
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
pub fn onCallAudioEv(ctx: *anyopaque, from: *const engine_mod.Contact, seq: u32, data: []const u8) void {
    // ВЫЗЫВАЕТСЯ ПОД app.mu (из envIn) — второго захвата быть не должно.
    const app: *App = @ptrCast(@alignCast(ctx));
    const c = app.call orelse return;
    if (!c.up) return;
    if (c.cid != app_mod.contactIdByBundle(app, from.bundle) orelse return) return;
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

/// Открыть аудио (fifo) и запустить поток захвата микрофона.
pub fn startCallAudio(app: *App, c: *app_mod.CallState) void {
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
pub fn micLoop(app: *App) void {
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
pub fn jbufTick(app: *App, c: *app_mod.CallState) void {
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

pub const aead_min = 16; // aead.tag_length

pub fn isZero(b: []const u8) bool {
    for (b) |x| if (x != 0) return false;
    return true;
}

/// Завершить звонок: остановить поток, закрыть аудио, освободить состояние.
pub fn endCallLocked(app: *App, call_id: [16]u8) void {
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
    events.evCallState(app, cid, call_id, .end);
}

/// START_CALL: инициировать звонок. Ответ: [call_id 16].
pub fn apiStartCall(app: *App, payload: []const u8, w: *api.Writer) api.Status {
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
    const c = app.alloc.create(app_mod.CallState) catch return .INTERNAL;
    c.* = .{ .cid = @intCast(cid), .call_id = call_id, .secret = sess.callSecret(call_id), .start_ms = app.nowMs() };
    app.call = c;
    _ = app.eng.callSignal(@intCast(cid), audio_mod.CallOp.offer, call_id) catch {
        app.alloc.destroy(c);
        app.call = null;
        return .NO_SESSION;
    };
    events.evCallState(app, @intCast(cid), call_id, .offer);
    w.putBytes(&call_id) catch return .INTERNAL;
    return .OK;
}

/// ANSWER_CALL: принять входящий. Payload пуст, ответ пуст.
pub fn apiAnswerCall(app: *App, payload: []const u8, w: *api.Writer) api.Status {
    _ = w;
    if (payload.len != 0) return .BAD_FRAME;
    app.lock();
    defer app.unlock();
    const c = app.call orelse return .NO_CALL;
    if (c.up) return .OK; // уже в разговоре — идемпотентно
    if (c.start_ms == 0) c.start_ms = app.nowMs();
    _ = app.eng.callSignal(c.cid, audio_mod.CallOp.accept, c.call_id) catch return .NO_SESSION;
    startCallAudio(app, c);
    events.evCallState(app, c.cid, c.call_id, .accept);
    return .OK;
}

/// END_CALL: завершить/отклонить. Payload пуст, ответ пуст.
pub fn apiEndCall(app: *App, payload: []const u8, w: *api.Writer) api.Status {
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
