<p align="center">
  <img src="docs/assets/stille_logo.png" alt="stille-messenger logo" width="240">
</p>

<h1 align="center">stille-messenger-core</h1>

<p align="center">
  Serverless P2P messenger core: a Zig daemon that owns the cryptography,<br>
  sessions, delivery and storage. GUI clients render; the core does the rest.
</p>

<p align="center">
  <a href="https://ziglang.org/download/"><img src="https://img.shields.io/badge/Zig-0.17.0-f6a517" alt="Zig 0.17.0"></a>
  <img src="https://img.shields.io/badge/dependencies-std_only-3f6f8f" alt="std-only">
  <img src="https://img.shields.io/badge/wire_protocol-v5-3f6f8f" alt="wire protocol v5">
  <img src="https://img.shields.io/badge/UDS_API-2.10.0-3f6f8f" alt="UDS API 2.10.0">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-3f6f8f" alt="MIT license"></a>
</p>

**English** | [Русский](docs/ru/README.md)

The core is the whole messenger minus the interface: identity, the P2P wire
protocol, encryption, offline delivery, file transfer, voice calls, and the
encrypted local history. It has **zero servers of its own** — message history
lives on the two devices only; a relay is optional user-hosted software for
IP hiding. Implementation: pure Zig, std-only — no packages, no OS
dependencies. Source: [`core/`](core/).

There is no CLI/TUI for chatting: the only client interface is a binary
framed UDS protocol ([`core/docs/CORE-API.md`](core/docs/CORE-API.md), API
2.10.0). The C++ version (v0.2.4, FTXUI/MQTT/WebRTC) is removed from master;
the archive lives under the tag `cpp-archive`.

> [!NOTE]
> **Legacy compatibility:** on the first start the legacy data directory
> `~/.shopot` migrates atomically to `~/.stille-messenger` (if both exist,
> the core refuses to start instead of merging); legacy invitation prefixes
> (`shopot://i/`, `shopot://i3/`, `shopot1.`), the discovery marker and
> cryptographic domain strings retain their original values. Existing
> identities, encrypted history and protocol formats are unchanged.

## What the core does

| Area | Summary |
|---|---|
| Identity | X25519 + Ed25519 keypairs derived from one 32-byte seed (`~/.stille-messenger/zig-seed`, 0600) |
| Handshake | XX-like, hybrid post-quantum: X25519 + ephemeral ML-KEM-768 (FIPS 203), Ed25519 transcript signatures, remote-static verification |
| Transport | Direct TCP (ports 7777–7786), self-hosted relay with persistent presence, NAT traversal (simultaneous open over relay-reflexive candidates; relay stays the fallback), IPv6-direct and UPnP-mapped public endpoints (direct-first: the relay is rendezvous-only), LAN discovery over UDP multicast, Tor SOCKS5 dialing; wire disguised as TLS 1.3 |
| Messaging | Formatting entities (bold/italic/spoiler/code/link), replies, reactions, offline delivery (encrypted outbox, ACKs, dedup), resumable file transfer, 16 kHz E2EE voice calls (ADPCM, DTX) |
| Storage | Append-only AEAD log — zero plaintext bytes on disk |
| Interface | Binary framed UDS API (`~/.stille-messenger/api.sock`) — the only interface |
| Recovery | Access without history: passkey (WebAuthn PRF) or recovery code unlocks a sealed backup blob (identity + profile + contacts) stored in the user's own cloud |

Adding a contact is one action: `CREATE_INVITE` produces a one-time
`stille://i/...` code; the holder performs exactly one `ACCEPT_INVITE`. The
core verifies the signed, HMAC-authenticated JOIN and adds the peer
automatically — no second key, no manual confirmation.

## Architecture

Six layers with a one-way dependency direction; modules talk to interfaces
(`Conn`/`Transport`/`Clock`), concrete implementations are injected — which is
what makes the core testable without sockets:

```
app      daemon: invites, LAN discovery, autodial, recovery, UDS API server
  │
engine   contacts, dispatch, outbox, file-transfer state machines
  │
session  handshake + sealed frames
  │
proto    allocation-free envelope codec      crypto   identity, ratchet, AEAD
net      TCP, fake-TLS, relay, SOCKS5        store    AEAD append-only log
```

The app layer is the only one that dials: it wraps a raw transport connection
into an obfuscated `interfaces.Conn` and hands it to the engine — sessions
never see a socket. Full layer/data-flow/threading reference with a module
dependency diagram: [`core/docs/ARCHITECTURE.md`](core/docs/ARCHITECTURE.md).

## Cryptography

- Hybrid handshake: classical security holds while X25519 **or** ML-KEM-768
  stays unbroken, so recorded traffic resists store-now-decrypt-later.
  Authentication remains Ed25519 (classical) — an active quantum MITM during
  the handshake is a documented limitation.
- Double encryption of messages: per-message ratchet keys on top of the
  transport AEAD stream; X25519 epoch rotation every 256 sent messages
  (post-compromise security).
- Calls: 20 ms frames, per-frame key = HKDF(call_secret, seq).
- Storage: append-only AEAD log with counter-derived nonces.

Byte-level specification: [`core/docs/PROTOCOL.md`](core/docs/PROTOCOL.md).
Threat model and cryptographic inventory: [SECURITY.md](SECURITY.md).

## Build

Requires [Zig 0.17.0](https://ziglang.org/download/) only.

```bash
make            # = cd core && zig build -Doptimize=ReleaseFast
make test       # = cd core && zig build test --summary all
```

Binary: `core/zig-out/bin/stille-messenger-core`. Release builds for
x86_64-linux-musl and aarch64-macos are attached to every `zig-v*` tag.

## Running

```bash
stille-messenger-core init          # identity: ~/.stille-messenger/zig-seed (0600)
stille-messenger-core serve         # daemon: core + UDS API (~/.stille-messenger/api.sock)
```

`serve` without a seed file starts unprovisioned and waits for
[`RESTORE_RECOVERY_BACKUP`](core/docs/CORE-API.md#410-account-recovery-since-api-260)
— the account-recovery path for a lost device (details in
[CLIENT_RULES.md](CLIENT_RULES.md)).

## Relay (IP hiding)

```bash
# on any server (VPS):
./stille-messenger-core relay 0.0.0.0:9000
```

The relay is a stateless byte split: it holds no stille-messenger state and
no keys. A peer issues a relay invite (`CREATE_INVITE_EX` mode 2 via the UDS
API); the code holder connects through the relay and never sees the
inviter's IP. After the first JOIN the contact remembers the relay address
and re-pairs automatically — no new invite needed. Specification:
[PROTOCOL.md §15](core/docs/PROTOCOL.md#15-relay-ip-hiding).

## Documentation

| Document | Content |
|---|---|
| [`core/docs/CORE-API.md`](core/docs/CORE-API.md) / [ru](core/docs/ru/CORE-API.md) | binary UDS interface for GUI clients (API 2.10.0) |
| [`CLIENT_RULES.md`](CLIENT_RULES.md) / [ru](docs/ru/CLIENT_RULES.md) | binding contract for GUI clients: bootstrap, events, account recovery UX |
| [`core/docs/PROTOCOL.md`](core/docs/PROTOCOL.md) / [ru](core/docs/ru/PROTOCOL.md) | byte-level wire protocol v5 |
| [`core/docs/ARCHITECTURE.md`](core/docs/ARCHITECTURE.md) / [ru](core/docs/ru/ARCHITECTURE.md) | layers, data flow, threading |
| [`core/docs/ROADMAP.md`](core/docs/ROADMAP.md) / [ru](core/docs/ru/ROADMAP.md) | technical plan and anti-plan |
| [SECURITY.md](SECURITY.md) / [ru](docs/ru/SECURITY.md) | threat model, reporting, crypto inventory |
| [CONTRIBUTING.md](CONTRIBUTING.md) / [ru](docs/ru/CONTRIBUTING.md) | contribution rules (kernel-style) |
| [docs/DOCSTYLE.md](docs/DOCSTYLE.md) / [ru](docs/ru/DOCSTYLE.md) | binding rules for writing documentation |

## Official client

- Second project developer: [EryyynIT](https://github.com/EryyynIT)
- Official stille-messenger client: [stille-messenger](https://github.com/EryyynIT/stille-messenger)

## License

MIT — see [LICENSE](LICENSE).
