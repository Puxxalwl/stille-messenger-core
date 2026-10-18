//! stille-messenger: serverless encrypted messenger core. std-only.
pub const interfaces = @import("stille-messenger/core/interfaces.zig");

pub const crypto = struct {
    pub const kdf = @import("stille-messenger/crypto/kdf.zig");
    pub const aead = @import("stille-messenger/crypto/aead.zig");
    pub const identity = @import("stille-messenger/crypto/identity.zig");
    pub const handshake = @import("stille-messenger/crypto/handshake.zig");
    pub const ratchet = @import("stille-messenger/crypto/ratchet.zig");
    pub const call_keys = @import("stille-messenger/crypto/call_keys.zig");
    pub const pad = @import("stille-messenger/crypto/pad.zig");
    pub const recovery = @import("stille-messenger/crypto/recovery.zig");
};

pub const proto = struct {
    pub const codec = @import("stille-messenger/proto/codec.zig");
    pub const envelope = @import("stille-messenger/proto/envelope.zig");
};

pub const net = struct {
    pub const framing = @import("stille-messenger/net/framing.zig");
    pub const faketls = @import("stille-messenger/net/faketls.zig");
    pub const relay = @import("stille-messenger/net/relay.zig");
    pub const obfuscate = @import("stille-messenger/net/obfuscate.zig");
    pub const heartbeat = @import("stille-messenger/net/heartbeat.zig");
    pub const tcp = @import("stille-messenger/net/tcp.zig");
    pub const socks5 = @import("stille-messenger/net/socks5.zig");
    pub const sysfd = @import("stille-messenger/net/sysfd.zig");
};

pub const store = struct {
    pub const log = @import("stille-messenger/store/log.zig");
};

/// Прикладной слой (демон): синхронизация устройств и конфигурация —
/// части контракта wire, доступные интеграционным тестам.
pub const app = struct {
    pub const sync = @import("stille-messenger/app/sync.zig");
    pub const config = @import("stille-messenger/app/config.zig");
};

test {
    std.testing.refAllDecls(@This());
}
const std = @import("std");

pub const core = struct {
    pub const interfaces = @import("stille-messenger/core/interfaces.zig");
    pub const session = @import("stille-messenger/core/session.zig");
    pub const engine = @import("stille-messenger/core/engine.zig");
};
