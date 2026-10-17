//! Тестовый корень модуля: zig build test гоняет через этот файл тесты
//! ВСЕХ подмодулей (тесты файлов, импортированных только внутри вложенных
//! контейнеров stille-messenger.zig, компилятором не собираются — здесь импорт явный).
test {
    _ = @import("stille-messenger/core/interfaces.zig");
    _ = @import("stille-messenger/core/session.zig");
    _ = @import("stille-messenger/core/engine.zig");
    _ = @import("stille-messenger/crypto/kdf.zig");
    _ = @import("stille-messenger/crypto/aead.zig");
    _ = @import("stille-messenger/crypto/identity.zig");
    _ = @import("stille-messenger/crypto/handshake.zig");
    _ = @import("stille-messenger/crypto/ratchet.zig");
    _ = @import("stille-messenger/crypto/call_keys.zig");
    _ = @import("stille-messenger/crypto/pad.zig");
    _ = @import("stille-messenger/proto/codec.zig");
    _ = @import("stille-messenger/proto/envelope.zig");
    _ = @import("stille-messenger/net/framing.zig");
    _ = @import("stille-messenger/net/obfuscate.zig");
    _ = @import("stille-messenger/net/faketls.zig");
    _ = @import("stille-messenger/net/relay.zig");
    _ = @import("stille-messenger/net/heartbeat.zig");
    _ = @import("stille-messenger/net/tcp.zig");
    _ = @import("stille-messenger/net/socks5.zig");
    _ = @import("stille-messenger/app/adpcm.zig");
    _ = @import("stille-messenger/app/api.zig");
    _ = @import("stille-messenger/app/config.zig");
    _ = @import("stille-messenger/app/sync.zig");
    _ = @import("stille-messenger/app/search.zig");
    _ = @import("stille-messenger/store/log.zig");
}
