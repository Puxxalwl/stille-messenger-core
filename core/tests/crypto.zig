//! Корень crypto-тестов: модульные тесты криптомодулей ядра (aead, kdf,
//! identity, handshake, ratchet, call_keys, pad, recovery). Тела — в
//! tests/crypto/*.zig; приватный доступ не нужен — публичный API
//! библиотеки через импорт stille-messenger. Корневой шаг — test-crypto
//! (zig build test-crypto).
test {
    _ = @import("crypto/aead_tests.zig");
    _ = @import("crypto/call_keys_tests.zig");
    _ = @import("crypto/handshake_tests.zig");
    _ = @import("crypto/identity_tests.zig");
    _ = @import("crypto/kdf_tests.zig");
    _ = @import("crypto/pad_tests.zig");
    _ = @import("crypto/ratchet_tests.zig");
    _ = @import("crypto/recovery_tests.zig");
}
