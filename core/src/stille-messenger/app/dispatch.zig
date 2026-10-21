//! Диспетчер API: разбор ApiRequest, вызов обработчика, отправка
//! ровно одного ответа. CLOSE — разрыв соединения.
const std = @import("std");
const stille_messenger = @import("stille-messenger");
const config_mod = stille_messenger.app.config;
const api = @import("api.zig");
const api_srv = @import("api_server.zig");
const app_mod = @import("app.zig");
const App = app_mod.App;
const handlers = @import("api_handlers.zig");
const invites = @import("invites.zig");
const calls = @import("calls.zig");
const presence = @import("presence.zig");

/// Маппинг error set'ов ядра на статусы API.
pub fn statusOf(e: anyerror) api.Status {
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

/// Диспетчер API-методов: разбирает payload, исполняет, шлёт ровно один
/// ответ. Возвращает false — сервер закрывает соединение (CLOSE).
pub fn dispatchApi(app: *App, conn: *api_srv.Conn, req: api.ApiRequest) bool {
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
        .GET_IDENTITY => respond(conn, req, handlers.apiGetIdentity(app, req.payload, &w), w.items()),
        .CREATE_INVITE => respond(conn, req, invites.apiCreateInvite(app, req.payload, &w), w.items()),
        .ACCEPT_INVITE => respond(conn, req, invites.apiAcceptInvite(app, req.payload, &w), w.items()),
        .LIST_CONTACTS => respond(conn, req, handlers.apiListContacts(app, req.payload, &w), w.items()),
        .SEND_MESSAGE => respond(conn, req, handlers.apiSendMessage(app, req.payload, &w), w.items()),
        .SEND_REPLY_MESSAGE => respond(conn, req, handlers.apiSendReplyMessage(app, req.payload, &w), w.items()),
        .SET_REACTION => respond(conn, req, handlers.apiReaction(app, req.payload, true), w.items()),
        .REMOVE_REACTION => respond(conn, req, handlers.apiReaction(app, req.payload, false), w.items()),
        .GET_REACTIONS => respond(conn, req, handlers.apiGetReactions(app, req.payload, &w), w.items()),
        .GET_HISTORY => respond(conn, req, handlers.apiGetHistory(app, req.payload, &w), w.items()),
        .GET_MESSAGE => respond(conn, req, handlers.apiGetMessage(app, req.payload, &w), w.items()),
        .SEARCH_MESSAGE => respond(conn, req, handlers.apiSearchMessage(app, req.payload, &w), w.items()),
        .GLOBAL_SEARCH_MESSAGE => respond(conn, req, handlers.apiGlobalSearchMessage(app, req.payload, &w), w.items()),
        .PIN_CHAT => respond(conn, req, handlers.apiPinChat(app, req.payload, &w), w.items()),
        .GET_PINNED_CHAT => respond(conn, req, handlers.apiGetPinnedChat(app, req.payload, &w), w.items()),
        .UNPIN_CHAT => respond(conn, req, handlers.apiUnpinChat(app, req.payload, &w), w.items()),
        .DELETE_CHAT => respond(conn, req, handlers.apiDeleteChat(app, req.payload, &w), w.items()),
        .GET_CONTACT_STATE => respond(conn, req, handlers.apiGetContactState(app, req.payload, &w), w.items()),
        .ACCEPT_INVITE_EX => respond(conn, req, invites.apiAcceptInviteEx(app, req.payload, &w), w.items()),
        .SUBSCRIBE_CONTACT_UPDATES => respond(conn, req, handlers.apiSubscribeContactUpdates(app, conn, req.payload, &w), w.items()),
        .GET_BOOTSTRAP => respond(conn, req, handlers.apiGetBootstrap(app, req.payload, &w), w.items()),
        .GET_CONTACTS_DELTA => respond(conn, req, handlers.apiGetContactsDelta(app, req.payload, &w), w.items()),
        .GET_REACHABLE_ENDPOINTS => respond(conn, req, handlers.apiGetReachableEndpoints(app, req.payload, &w), w.items()),
        .CREATE_INVITE_EX => respond(conn, req, invites.apiCreateInviteEx(app, req.payload, &w), w.items()),
        .GET_INVITE_STATE => respond(conn, req, invites.apiGetInviteState(app, req.payload, &w), w.items()),
        .GENERATE_SHORT_CODE => respond(conn, req, invites.apiGenerateShortCode(app, req.payload, &w), w.items()),
        .DECODE_SHORT_CODE => respond(conn, req, invites.apiDecodeShortCode(app, req.payload, &w), w.items()),
        .REGENERATE_PROFILE_CODE => respond(conn, req, invites.apiRegenerateProfileCode(app, req.payload, &w), w.items()),
        .GET_HISTORY_PAGE => respond(conn, req, handlers.apiGetHistoryPage(app, req.payload, &w), w.items()),
        .SEND_CONTACT => respond(conn, req, handlers.apiSendContact(app, req.payload, &w), w.items()),
        .PIN_MESSAGE => respond(conn, req, handlers.apiPinMessage(app, req.payload, &w), w.items()),
        .UNPIN_MESSAGE => respond(conn, req, handlers.apiUnpinMessage(app, req.payload, &w), w.items()),
        .GET_PINNED_MESSAGES => respond(conn, req, handlers.apiGetPinnedMessages(app, req.payload, &w), w.items()),
        .SET_NAME => respond(conn, req, handlers.apiSetName(app, req.payload, &w), w.items()),
        .SET_AVATAR => respond(conn, req, handlers.apiSetAvatar(app, req.payload, &w), w.items()),
        .GET_MY_AVATAR => respond(conn, req, handlers.apiGetMyAvatar(app, req.payload, &w), w.items()),
        .CREATE_RECOVERY_BACKUP => respond(conn, req, handlers.apiCreateRecoveryBackup(app, req.payload, &w), w.items()),
        .RESTORE_RECOVERY_BACKUP => respond(conn, req, handlers.apiRestoreRecoveryBackup(app, req.payload, &w), w.items()),
        .GET_AVATAR_ID => respond(conn, req, handlers.apiGetAvatarId(app, req.payload, &w), w.items()),
        .SEND_FILE => respond(conn, req, handlers.apiSendFile(app, req.payload, &w), w.items()),
        .START_CALL => respond(conn, req, calls.apiStartCall(app, req.payload, &w), w.items()),
        .ANSWER_CALL => respond(conn, req, calls.apiAnswerCall(app, req.payload, &w), w.items()),
        .END_CALL => respond(conn, req, calls.apiEndCall(app, req.payload, &w), w.items()),
        .BLOCK_CONTACT => respond(conn, req, handlers.apiBlock(app, req.payload, true), w.items()),
        .UNBLOCK_CONTACT => respond(conn, req, handlers.apiBlock(app, req.payload, false), w.items()),
        .CONNECT => respond(conn, req, handlers.apiConnect(app, req.payload, &w), w.items()),
        .LISTEN => respond(conn, req, handlers.apiListen(app, req.payload, &w), w.items()),
        .GET_CONFIG => respond(conn, req, handlers.apiGetConfig(app, req.payload, &w), w.items()),
        .SET_CONFIG => respond(conn, req, handlers.apiSetConfig(app, req.payload, &w), w.items()),
        .WRITE_DB => respond(conn, req, handlers.apiWriteDb(app, req.payload, &w), w.items()),
        .READ_DB => respond(conn, req, handlers.apiReadDb(app, req.payload, &w), w.items()),
        .DELETE_DB => respond(conn, req, handlers.apiDeleteDb(app, req.payload, &w), w.items()),
    }
    return true;
}

/// Отправить ответ метода (единая точка).
pub fn respond(conn: *api_srv.Conn, req: api.ApiRequest, status: api.Status, payload: []const u8) void {
    conn.sendResponse(@backingInt(req.method), req.request_id, status, payload);
}

/// INTERNAL при переполнении сборщика ответа.
pub fn internal(conn: *api_srv.Conn, req: api.ApiRequest) bool {
    conn.sendResponse(@backingInt(req.method), req.request_id, .INTERNAL, &.{});
    return true;
}
