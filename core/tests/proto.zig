//! Корень proto-тестов: конформанс протокола конвертов. Тела — в
//! tests/proto/*.zig; ко-located инварианты файлов proto/ остаются в
//! test-unit (корень библиотеки), если требуют приватного доступа.
test {
    _ = @import("proto/envelope_tests.zig");
}
