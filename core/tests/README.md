# Тесты ядра (core/tests/)

**Policy (EN, normative):** test roots and test bodies live in `tests/`,
never in `src/` — co-location in `src/` is reserved for tests that
exercise a file's private declarations plus pure aggregation blocks in
module roots. Build steps: `test-unit`, `test-proto`, `test-crypto`,
`test-app`, `test-integration`, `bench`; the default `test` step runs
all but `bench`. The Russian text below is the detailed same-commit
mirror.

**Правило: тела и корни тестов живут здесь, не в `src/`.** Zig компилирует
блоки `test` только в корне теста, поэтому корни заданы явно в `build.zig`;
файл может принадлежать только одному модулю компиляции — отсюда и структура
ниже.

| шаг zig build | корень | тела | что покрывает |
|---|---|---|---|
| `test-unit` | `src/stille-messenger.zig` (библиотека в тест-режиме) | ко-located блоки в `src/` | инварианты приватных внутренностей: session, engine, log, большинство net/* |
| `test-proto` | `tests/proto.zig` | `tests/proto/` | конформанс протокола конвертов: roundtrip, раскладки байтов, строгий decode |
| `test-crypto` | `tests/crypto.zig` | `tests/crypto/` | конформанс криптографии: handshake, ratchet, recovery, aead, kdf, identity, pad, call keys |
| `test-app` | `src/stille-messenger/app/main.zig` + `tests/app.zig` | ко-located в дереве app + тела в `tests/app.zig` | тесты файлов демона (invites, endpoints, wake, discover, api, adpcm, audio, search, recovery) и сценарии демона поверх loopback-порта |
| `test-integration` | `tests/integration.zig` | он же | сквозные сценарии двух сторон: handshake → сообщения → ротация → реконнект |
| `bench` | `tests/bench_transport.zig` (ReleaseFast) | он же | бенчмарк транспорта |

`zig build test` запускает всё, кроме `bench`.

## Почему часть тестов осталась в src/

Блок `test` может видеть только декларации своего файла/модуля. Тесты
приватных внутренностей (например, `core/session.zig`, `store/log.zig`)
физически не могут переехать в `tests/` без публикации внутренностей в
публичный API — это противоречит правилу минимального API. Такие файлы
держат тесты рядом с кодом и попадают в `test-unit` через явный блок
агрегации в корне библиотеки:

```zig
test {
    _ = @import("core/session.zig");
    // ...
}
```

Тот же приём собирает ко-located тесты дерева демона: блок агрегации в
`app/main.zig` (файлы app-слоя обязаны принадлежать одному модулю —
`app-main` — поэтому их тесты собирает корень этого дерева, а не корень
библиотеки).

## Соглашения

- Тела тестов в `tests/` обращаются к коду приложения только через импорты
  модулей (`@import("stille-messenger")`, `@import("app-main")`) —
  относительный путь из `tests/` в `src/` запрещён ограничением модуля Zig
  ("import of file outside module path").
- Тесты не зависят от внешней сети и стеночных часов; где нужно — реальные
  loopback-порты с фиксированными диапазонами и инжектированное время.
- Перенос теста в `tests/` — вербатимный: логика, имена и ожидаемые
  значения не меняются (иначе diff скрывает смену поведения).
