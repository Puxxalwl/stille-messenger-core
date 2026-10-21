<p align="center">
  <img src="../assets/stille_logo.png" alt="Логотип stille-messenger" width="240">
</p>

<h1 align="center">stille-messenger-core</h1>

<p align="center">
  Ядро серверлесс P2P-мессенджера: Zig-демон, которому принадлежат криптография,<br>
  сессии, доставка и хранение. GUI-клиент рендерит; остальное делает ядро.
</p>

<p align="center">
  <a href="https://ziglang.org/download/"><img src="https://img.shields.io/badge/Zig-0.17.0-f6a517" alt="Zig 0.17.0"></a>
  <img src="https://img.shields.io/badge/dependencies-std_only-3f6f8f" alt="std-only">
  <img src="https://img.shields.io/badge/wire_protocol-v5-3f6f8f" alt="протокол v5">
  <img src="https://img.shields.io/badge/UDS_API-2.10.0-3f6f8f" alt="UDS API 2.10.0">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-3f6f8f" alt="лицензия MIT"></a>
</p>

[English](../../README.md) | **Русский**

Ядро — это весь мессенджер без интерфейса: личность, P2P-протокол, шифрование,
доставка офлайн, передача файлов, голосовые звонки и локальная шифрованная
история. **Ноль своих серверов** — история сообщений живёт только на двух
устройствах; релей — опциональное ПО пользователя для скрытия IP. Реализация:
чистый Zig, std-only — без пакетов и зависимостей от ОС. Исходники:
[`core/`](../../core/).

CLI/TUI для переписки нет: единственный клиентский интерфейс — бинарный
кадровый протокол UDS ([`core/docs/ru/CORE-API.md`](../../core/docs/ru/CORE-API.md),
API 2.10.0). C++-версия (v0.2.4, FTXUI/MQTT/WebRTC) удалена из master; архив —
тег `cpp-archive`.

> [!NOTE]
> **Legacy-совместимость:** при первом запуске каталог данных `~/.shopot`
> атомарно переносится в `~/.stille-messenger` (если существуют оба, ядро
> отказывается запускаться вместо молчаливого слияния); старые префиксы
> приглашений (`shopot://i/`, `shopot://i3/`, `shopot1.`), маркер обнаружения
> и криптографические домены сохраняют прежние значения. Существующие
> личности, зашифрованная история и форматы протокола не изменены.

## Что делает ядро

| Область | Суть |
|---|---|
| Идентичность | пары X25519 + Ed25519, выведенные из одного сида 32 байта (`~/.stille-messenger/zig-seed`, 0600) |
| Рукопожатие | XX-подобное, гибридное постквантовое: X25519 + эфемерный ML-KEM-768 (FIPS 203), подписи транскрипта Ed25519, сверка remote static |
| Транспорт | прямой TCP (порты 7777–7786), само-хостнутый релей с постоянным присутствием, NAT-обход (одновременный open по рефлексивным кандидатам релея; релей остаётся фолбэком), IPv6-прямые и UPnP-замапленные публичные endpoints (direct-first: релей — только рандеву), LAN-обнаружение через UDP-мультикаст, dial через Tor SOCKS5; провод замаскирован под TLS 1.3 |
| Сообщения | форматирование (bold/italic/spoiler/code/link), ответы, реакции, доставка офлайн (шифрованный outbox, ACK, дедуп), файлы с докачкой, звонки 16 кГц E2EE (ADPCM, DTX) |
| Хранилище | append-only AEAD-лог — ноль байт открытого текста на диске |
| Интерфейс | бинарный кадровый протокол UDS (`~/.stille-messenger/api.sock`) — единственный интерфейс |
| Восстановление | доступ без истории: passkey (WebAuthn PRF) или код восстановления открывают запечатанный блоб (личность + профиль + контакты) в личном облаке пользователя |

Добавление контакта — одно действие: `CREATE_INVITE` создаёт одноразовый код
`stille://i/...`; держатель выполняет ровно один `ACCEPT_INVITE`. Ядро
проверяет подписанный JOIN с HMAC и добавляет пира автоматически — без
второго ключа и ручного подтверждения.

## Архитектура

Шесть слоёв с однонаправленными зависимостями; модули работают через
интерфейсы (`Conn`/`Transport`/`Clock`), конкретные реализации внедряются —
благодаря этому ядро тестируется без сокетов:

```
app      демон: инвайты, LAN-обнаружение, автодозвон, восстановление, UDS-апи
  │
engine   контакты, dispatch, outbox, стейт-машины передачи файлов
  │
session  рукопожатие + sealed-кадры
  │
proto    кодек конвертов без аллокаций     crypto   identity, рэтчет, AEAD
net      TCP, fake-TLS, релей, SOCKS5       store    AEAD append-only лог
```

Диалит только слой app: он оборачивает сырое транспортное соединение в
обфусцированный `interfaces.Conn` и передаёт его движку — сессия сокета не
видит вообще. Полный справочник по слоям, потокам данных и тредингу с
диаграммой зависимостей: [`core/docs/ru/ARCHITECTURE.md`](../../core/docs/ru/ARCHITECTURE.md).

## Криптография

- Гибридное рукопожатие: классическая безопасность держится, пока цел
  X25519 **или** ML-KEM-768 — записанный сегодня трафик устойчив к
  store-now-decrypt-later. Аутентификация остаётся Ed25519 (классической) —
  активный квантовый MITM в рукопожатии документирован как ограничение.
- Двойное шифрование сообщений: ключи рэтчета на каждое сообщение поверх
  AEAD-потока; ротация эпох X25519 каждые 256 отправленных сообщений
  (post-compromise security).
- Звонки: кадры 20 мс, ключ кадра = HKDF(секрет звонка, seq).
- Хранилище: append-only AEAD-лог с counter-derived nonce.

Байтовая спецификация: [`core/docs/ru/PROTOCOL.md`](../../core/docs/ru/PROTOCOL.md).
Модель угроз и инвентаризация крипты: [SECURITY.md](SECURITY.md).

## Сборка

Нужен только [Zig 0.17.0](https://ziglang.org/download/).

```bash
make            # = cd core && zig build -Doptimize=ReleaseFast
make test       # = cd core && zig build test --summary all
```

Бинарник: `core/zig-out/bin/stille-messenger-core`. Релизные сборки под
x86_64-linux-musl и aarch64-macos прикрепляются к каждому тегу `zig-v*`.

## Запуск

```bash
stille-messenger-core init     # личность: ~/.stille-messenger/zig-seed (0600)
stille-messenger-core serve    # демон: ядро + UDS-апи (~/.stille-messenger/api.sock)
```

`serve` без файла сида стартует непровижненным и ждёт
[`RESTORE_RECOVERY_BACKUP`](../../core/docs/ru/CORE-API.md#410-восстановление-доступа-начиная-с-api-260)
— путь восстановления аккаунта на потерянном устройстве (детали в
[CLIENT_RULES.md](CLIENT_RULES.md)).

## Релей (скрытие IP)

```bash
# на любом сервере (VPS):
./stille-messenger-core relay 0.0.0.0:9000
```

Релей — байтовый сплит без состояния: он не хранит ни состояние
stille-messenger, ни ключи. Пир выпускает релей-инвайт (`CREATE_INVITE_EX`
mode 2 через UDS-апи); держатель кода подключается через релей и никогда не
видит IP приглашающего. После первого JOIN контакт запоминает адрес релея и
спаривается заново автоматически — новый инвайт не нужен. Спецификация:
[PROTOCOL.md §15](../../core/docs/ru/PROTOCOL.md#15-релей-скрытие-ip).

## Документация

| Документ | Содержание |
|---|---|
| [`core/docs/ru/CORE-API.md`](../../core/docs/ru/CORE-API.md) / [en](../../core/docs/CORE-API.md) | бинарный UDS-интерфейс для GUI-клиентов (API 2.10.0) |
| [`docs/ru/CLIENT_RULES.md`](CLIENT_RULES.md) / [en](../../CLIENT_RULES.md) | обязательный контракт GUI-клиентов: бутстрап, события, UX восстановления |
| [`core/docs/ru/PROTOCOL.md`](../../core/docs/ru/PROTOCOL.md) / [en](../../core/docs/PROTOCOL.md) | байтовая спецификация провода v5 |
| [`core/docs/ru/ARCHITECTURE.md`](../../core/docs/ru/ARCHITECTURE.md) / [en](../../core/docs/ARCHITECTURE.md) | слои, потоки данных, трединг |
| [`core/docs/ru/ROADMAP.md`](../../core/docs/ru/ROADMAP.md) / [en](../../core/docs/ROADMAP.md) | технический план и анти-план |
| [SECURITY.md](SECURITY.md) / [en](../../SECURITY.md) | модель угроз, репортинг, инвентаризация крипты |
| [CONTRIBUTING.md](CONTRIBUTING.md) / [en](../../CONTRIBUTING.md) | правила контрибуции (kernel-style) |
| [DOCSTYLE.md](DOCSTYLE.md) / [en](../../docs/DOCSTYLE.md) | обязательные правила написания доков |

## Официальный клиент

- Второй разработчик проекта stille-messenger: [EryyynIT](https://github.com/EryyynIT)
- Официальный клиент stille-messenger: [stille-messenger](https://github.com/EryyynIT/stille-messenger)

## Лицензия

MIT — см. [LICENSE](../../LICENSE).
